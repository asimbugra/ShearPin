/**
 * off-chain counterparty signal enrichment.
 *
 * the contract's check_counterparty verdict (blocklist + allowlist) is the
 * source of truth for block decisions — this layer NEVER downgrades a
 * verdict. it adds risk reasons from three best-effort, off-chain signals
 * (account age/activity, contract code change, prior interactions) and can
 * upgrade allow -> warn so a human takes a look before signing.
 *
 * every signal degrades gracefully: a missing api key, a network error or a
 * timeout yields a "signal unavailable" note — never a false decision.
 */
import { keccak256 } from "ethers";

export interface CodeStore {
  /** returns the last observed code hash for the address, or null if never seen */
  get(address: string): string | null;
  set(address: string, codeHash: string): void;
}

export interface SignalReport {
  /** signal name: "account-age" | "contract" | "prior-interactions" */
  name: string;
  /** human-readable observed value, or "unavailable" */
  value: string;
  /** true if this signal contributed a warn-level risk reason */
  risk: boolean;
  /** risk or unavailability note surfaced into reasons */
  reason?: string;
}

export interface EnrichedVerdict {
  verdict: "allow" | "warn" | "block";
  reasons: string[];
  signals: SignalReport[];
}

export interface SignalOptions {
  /** Etherscan API key — without it the account-age and prior-interactions signals degrade */
  etherscanApiKey?: string;
  /** Etherscan V2 base url (default https://api.etherscan.io/v2/api) */
  etherscanApiUrl?: string;
  /** chain id for the Etherscan V2 multichain API (default 11155111 = Sepolia) */
  chainId?: number;
  /** EVM JSON-RPC endpoint for eth_getCode — without it the contract signal degrades */
  evmRpcUrl?: string;
  /** the paying agent's EOA — enables the prior-interactions signal */
  agentEoa?: string;
  /** code-hash memory for the code-change signal (default: in-process map) */
  codeStore?: CodeStore;
  /** injectable fetch (tests / custom agents) */
  fetchFn?: typeof fetch;
  /** injectable clock in ms (tests) */
  now?: () => number;
  /** per-signal timeout in ms (default 5000) */
  timeoutMs?: number;
}

/** warn thresholds */
const YOUNG_ACCOUNT_DAYS = 7;
const LOW_ACTIVITY_TXS = 3;
const ACTIVITY_WINDOW = 25;
const PRIOR_WINDOW = 100;

/** process-lifetime default code memory so repeated checks see changes */
const defaultCodeStore: CodeStore = (() => {
  const m = new Map<string, string>();
  return {
    get: (a) => m.get(a.toLowerCase()) ?? null,
    set: (a, h) => void m.set(a.toLowerCase(), h),
  };
})();

/** fetch json with a hard timeout; returns null instead of throwing */
async function fetchJson(
  url: string,
  init: RequestInit | undefined,
  fetchFn: typeof fetch,
  timeoutMs: number,
): Promise<unknown | null> {
  try {
    const res = await fetchFn(url, {
      ...init,
      signal: init?.signal ?? AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

interface EtherscanTx {
  timeStamp?: string;
  to?: string;
  isError?: string;
  hash?: string;
}

/** etherscan v2 txlist query; returns null when unreachable */
async function etherscanTxs(
  opts: Required<Pick<SignalOptions, "etherscanApiUrl" | "chainId">> & SignalOptions,
  address: string,
  sort: "asc" | "desc",
  offset: number,
  fetchFn: typeof fetch,
  timeoutMs: number,
): Promise<EtherscanTx[] | null> {
  const url =
    `${opts.etherscanApiUrl}?chainid=${opts.chainId}` +
    `&module=account&action=txlist&address=${address}` +
    `&startblock=0&endblock=99999999&page=1&offset=${offset}&sort=${sort}` +
    `&apikey=${opts.etherscanApiKey ?? ""}`;
  const body = (await fetchJson(url, undefined, fetchFn, timeoutMs)) as
    | { status?: string; result?: EtherscanTx[] }
    | null;
  if (!body || body.status !== "1" || !Array.isArray(body.result)) return null;
  return body.result;
}

/** eth_getCode via EVM JSON-RPC; returns null when unreachable */
async function ethGetCode(
  evmRpcUrl: string,
  address: string,
  fetchFn: typeof fetch,
  timeoutMs: number,
): Promise<string | null> {
  const body = (await fetchJson(
    evmRpcUrl,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getCode", params: [address, "latest"] }),
    },
    fetchFn,
    timeoutMs,
  )) as { result?: string } | null;
  return body?.result ?? null;
}

/** account age + recent activity from the receiver's first/last txs */
async function accountAgeSignal(
  opts: SignalOptions,
  address: string,
  fetchFn: typeof fetch,
  now: () => number,
  timeoutMs: number,
): Promise<SignalReport> {
  if (!opts.etherscanApiKey) {
    return { name: "account-age", value: "unavailable", risk: false, reason: "signal unavailable: account-age (no ETHERSCAN_API_KEY)" };
  }
  const base = {
    etherscanApiUrl: opts.etherscanApiUrl ?? "https://api.etherscan.io/v2/api",
    chainId: opts.chainId ?? 11155111,
  };
  const asc = await etherscanTxs({ ...opts, ...base }, address, "asc", 1, fetchFn, timeoutMs);
  if (!asc) {
    return { name: "account-age", value: "unavailable", risk: false, reason: "signal unavailable: account-age (etherscan request failed)" };
  }
  const reasons: string[] = [];
  let risk = false;
  let value = "no on-chain tx history found";
  const first = asc[0];
  if (first?.timeStamp) {
    const firstMs = Number(first.timeStamp) * 1000;
    const ageDays = (now() - firstMs) / DAY_MS;
    value = `first seen ${new Date(firstMs).toISOString().slice(0, 10)} (${ageDays.toFixed(1)}d old)`;
    if (ageDays < YOUNG_ACCOUNT_DAYS) {
      risk = true;
      reasons.push(`account is ${ageDays.toFixed(1)} days old (< ${YOUNG_ACCOUNT_DAYS} day threshold)`);
    }
  }
  const desc = await etherscanTxs({ ...opts, ...base }, address, "desc", ACTIVITY_WINDOW, fetchFn, timeoutMs);
  if (desc) {
    value += ` · ${desc.length} recent txs`;
    if (desc.length < LOW_ACTIVITY_TXS) {
      risk = true;
      reasons.push(`low activity: only ${desc.length} recent txs found`);
    }
  }
  return { name: "account-age", value, risk, reason: reasons.join("; ") || undefined };
}

/** contract vs EOA + code-change detection via eth_getCode */
async function contractSignal(
  opts: SignalOptions,
  address: string,
  fetchFn: typeof fetch,
  timeoutMs: number,
): Promise<SignalReport> {
  if (!opts.evmRpcUrl) {
    return { name: "contract", value: "unavailable", risk: false, reason: "signal unavailable: contract (no EVM_RPC_URL)" };
  }
  const code = await ethGetCode(opts.evmRpcUrl, address, fetchFn, timeoutMs);
  if (code === null) {
    return { name: "contract", value: "unavailable", risk: false, reason: "signal unavailable: contract (rpc request failed)" };
  }
  if (code === "0x") {
    return { name: "contract", value: "EOA (no code)", risk: false };
  }
  if (!/^0x([0-9a-fA-F]{2})*$/.test(code)) {
    return { name: "contract", value: "unavailable", risk: false, reason: "signal unavailable: contract (rpc returned a malformed code value)" };
  }
  const store = opts.codeStore ?? defaultCodeStore;
  const codeHash = keccak256(code);
  const prev = store.get(address);
  store.set(address, codeHash);
  if (prev && prev !== codeHash) {
    return {
      name: "contract",
      value: `contract, code ${codeHash}`,
      risk: true,
      reason: `contract code changed since last observation (${prev.slice(0, 10)}… -> ${codeHash.slice(0, 10)}…). selfdestruct-style upgrades and proxy swaps have happened to this address`,
    };
  }
  return {
    name: "contract",
    value: `contract, code ${codeHash}${prev ? "" : " (first observed — recorded)"}`,
    risk: false,
  };
}

/** prior successful transfers from the paying agent to this receiver */
async function priorInteractionsSignal(
  opts: SignalOptions,
  address: string,
  fetchFn: typeof fetch,
  timeoutMs: number,
): Promise<SignalReport> {
  if (!opts.etherscanApiKey || !opts.agentEoa) {
    return { name: "prior-interactions", value: "unavailable", risk: false, reason: "signal unavailable: prior-interactions (needs ETHERSCAN_API_KEY + agentEoa)" };
  }
  const base = {
    etherscanApiUrl: opts.etherscanApiUrl ?? "https://api.etherscan.io/v2/api",
    chainId: opts.chainId ?? 11155111,
  };
  const txs = await etherscanTxs({ ...opts, ...base }, opts.agentEoa, "desc", PRIOR_WINDOW, fetchFn, timeoutMs);
  if (!txs) {
    return { name: "prior-interactions", value: "unavailable", risk: false, reason: "signal unavailable: prior-interactions (etherscan request failed)" };
  }
  const target = address.toLowerCase();
  const ok = txs.filter((t) => t.to?.toLowerCase() === target && t.isError === "0");
  if (ok.length > 0) {
    return {
      name: "prior-interactions",
      value: `${ok.length} prior successful transfer(s) to this agent`,
      risk: false,
      reason: `prior history: ${ok.length} successful prior transfer(s) from this agent to the receiver`,
    };
  }
  return { name: "prior-interactions", value: "no prior transfers to this agent", risk: false };
}

const DAY_MS = 86_400_000;

/**
 * merge the contract's verdict with the three off-chain signals.
 * block stays block; allow + any risk signal upgrades to warn; all signal
 * reasons (risk, informational and unavailable notes) are appended.
 */
export async function enrichCounterparty(
  client: {
    checkCounterparty(
      policyId: string,
      address: string,
    ): Promise<{ verdict: "allow" | "warn" | "block"; reasons: string[] }>;
  },
  policyId: string,
  address: string,
  opts: SignalOptions = {},
): Promise<EnrichedVerdict> {
  const base = await client.checkCounterparty(policyId, address);
  const fetchFn = opts.fetchFn ?? fetch;
  const now = opts.now ?? Date.now;
  const timeoutMs = opts.timeoutMs ?? 5000;

  const signals = await Promise.all([
    accountAgeSignal(opts, address, fetchFn, now, timeoutMs),
    contractSignal(opts, address, fetchFn, timeoutMs),
    priorInteractionsSignal(opts, address, fetchFn, timeoutMs),
  ]);

  const reasons = [...base.reasons];
  for (const s of signals) {
    if (s.reason) reasons.push(s.reason);
  }
  const anyRisk = signals.some((s) => s.risk);
  const verdict = base.verdict === "block" ? "block" : anyRisk ? "warn" : base.verdict;
  return { verdict, reasons, signals };
}
