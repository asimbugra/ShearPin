/**
 * shearpin sdk — the agent only ever asks.
 *
 * flow: build RLP-encoded unsigned EIP-155 EVM tx -> contract parses it on-chain
 * to derive amount + recipient + chainId -> contract checks policy -> if allowed,
 * the contract itself requests the mpc signature -> we relay the signed tx
 * to the destination chain. denials panic inside the contract with a
 * SHEARPIN_* reason and never reach the mpc network at all.
 *
 * CRITICAL SECURITY: the agent NEVER claims an amount. the contract parses
 * the RLP payload and extracts value (amount), to (recipient), calldata
 * (ERC-20 transfer decoded), and chainId itself.
 *
 * tx format: EIP-155 (9 fields) [nonce, gasPrice, gasLimit, to, value, data,
 * chainId, 0, 0] — replay-protected; legacy 6-field txs are rejected by the
 * contract.
 *
 * calldata policy: empty = native transfer. non-empty MUST be an ERC-20
 * transfer (selector 0xa9059cbb); the contract decodes the real recipient
 * + amount from calldata and applies the same policy gates.
 */
import { JsonRpcProvider } from "@near-js/providers";
import { KeyPairSigner } from "@near-js/signers";
import { Account, JsonRpcProvider as NajProvider, KeyPairSigner as NajKeyPairSigner, actions as najActions } from "near-api-js";
import { ethers } from "ethers";
import { enrichCounterparty } from "./signals.js";
import type { SignalOptions } from "./signals.js";

export type { SignalOptions, SignalReport, EnrichedVerdict, CodeStore } from "./signals.js";
export { enrichCounterparty } from "./signals.js";

export type KeyType = "ecdsa" | "eddsa";

export interface PolicyView {
  owner: string;
  agent_label: string;
  max_tx: string;
  daily_limit: string;
  cooldown_blocks: number;
  rate_limit_per_day: number;
  spent_today: string;
  requests_today: number;
  tripped: boolean;
  frozen: boolean;
  status: string;
  allowed_recipients: string[];
  allowed_chain_ids: number[];
}

/** RLP-encoded unsigned EIP-155 EVM transaction (agent submits this, contract parses it) */
export interface SpendRequest {
  policyId: string;
  /** sub-path under the policy namespace, e.g. "eth/0" */
  derivationPath: string;
  keyType: KeyType;
  /** RLP-encoded unsigned EIP-155 tx: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0] */
  payload: Uint8Array;
}

export interface SpendOutcome {
  verdict: "allow" | "deny";
  reason?: string;
  nearTxHash?: string;
  logs?: string[];
}

export interface ShearPinConfig {
  network: "testnet" | "mainnet";
  contractId: string;
  /** near account of the agent runtime (holds a function-call key) */
  signerAccountId: string;
  /** ed25519 secret key of that account */
  signerSecretKey: string;
}

const TGAS = 10n ** 12n;

export class ShearPinClient {
  private provider: JsonRpcProvider;
  private account: Account;
  private cfg: ShearPinConfig;

  constructor(cfg: ShearPinConfig) {
    this.cfg = cfg;
    const rpc =
      cfg.network === "testnet"
        ? "https://rpc.testnet.fastnear.com"
        : "https://rpc.mainnet.near.org";
    this.provider = new JsonRpcProvider({ url: rpc });
    const najProvider = new NajProvider({ url: rpc });
    const najSigner = NajKeyPairSigner.fromSecretKey(cfg.signerSecretKey as never);
    this.account = new Account(cfg.signerAccountId, najProvider, najSigner);
  }

  private async callView<T>(method: string, args: Record<string, unknown>): Promise<T> {
    const res = await this.provider.query({
      request_type: "call_function",
      account_id: this.cfg.contractId,
      method_name: method,
      args_base64: Buffer.from(JSON.stringify(args)).toString("base64"),
      finality: "optimistic",
    });
    const raw = (res as unknown as { result: number[] }).result;
    return JSON.parse(Buffer.from(raw).toString("utf8"));
  }

  async getPolicy(policyId: string): Promise<PolicyView> {
    return this.callView("get_policy", { policy_id: policyId });
  }

  async status(policyId: string): Promise<string> {
    return this.callView("policy_status", { policy_id: policyId });
  }

  /**
   * counterparty check (the agent-side wrapper's data source).
   * asks the contract for allow | warn | block + reasons BEFORE any
   * signing attempt. this is a view call — free, no tx, no signature.
   */
  async checkCounterparty(
    policyId: string,
    address: string,
  ): Promise<{ verdict: "allow" | "warn" | "block"; reasons: string[] }> {
    const raw = await this.callView<unknown>(
      "check_counterparty",
      { policy_id: policyId, address },
    );
    // the contract returns a Rust tuple [verdict, reasons]; accept both shapes
    if (Array.isArray(raw)) {
      return { verdict: raw[0] as "allow" | "warn" | "block", reasons: (raw[1] as string[]) ?? [] };
    }
    return raw as { verdict: "allow" | "warn" | "block"; reasons: string[] };
  }

  /** report a bad counterparty to the shared blocklist (evidence required;
   *  attaches the contract's REPORT_DEPOSIT anti-Sybil stake, 0.01 NEAR) */
  async reportCounterparty(
    address: string,
    category: string,
    evidence: string,
  ): Promise<void> {
    await this.account.signAndSendTransaction({
      receiverId: this.cfg.contractId,
      actions: [
        najActions.functionCall(
          "report",
          { address, category, evidence },
          BigInt(50) * TGAS,
          BigInt("10000000000000000000000"), // 0.01 NEAR — REPORT_DEPOSIT
        ),
      ],
    });
  }

  /**
   * guarded spend: the agent-side wrapper required by the AI-security
   * flow. refuses to even submit when the counterparty verdict is block;
   * asks a human when it is warn (onWarn must resolve true to proceed).
   * only an allow verdict (or an approved warn) reaches requestSpend —
   * where the on-chain gates check everything again.
   *
   * opts.enrich (signals.ts): when given, the contract verdict is merged
   * with off-chain signals (account age, contract code change, prior
   * interactions) — risk signals upgrade allow to warn so a human looks.
   */
  async guardedSpend(
    req: SpendRequest,
    recipient: string,
    onWarn: (reasons: string[]) => Promise<boolean>,
    opts?: {
      enrich?: SignalOptions;
      autoAllowApproved?: boolean;
      /** a client built with the OWNER key — signs set_allowed_recipients
       *  on an approved warn. never put the owner key on the agent runtime. */
      ownerClient?: ShearPinClient;
    },
  ): Promise<SpendOutcome | { kind: "refused"; verdict: string; reasons: string[] }> {
    const { verdict, reasons } = opts?.enrich
      ? await enrichCounterparty(this, req.policyId, recipient, opts.enrich)
      : await this.checkCounterparty(req.policyId, recipient);
    if (verdict === "block") {
      return { kind: "refused", verdict, reasons };
    }
    if (verdict === "warn") {
      const approved = await onWarn(reasons);
      if (!approved) {
        return { kind: "refused", verdict, reasons };
      }
      // the approving human IS the owner — vetting by approval means the
      // recipient joins the policy allowlist, otherwise the on-chain
      // recipient allowlist gate would deny the very spend the human just
      // approved (and snap the pin). pass ownerClient (a client built with
      // the OWNER key) so the OWNER signs set_allowed_recipients — the
      // agent's function-call key can't (methods: request_signature only),
      // and an owner key on the agent runtime would defeat the whole model.
      if (opts?.autoAllowApproved) {
        const vetting = opts.ownerClient ?? this;
        await vetting.addAllowedRecipient(req.policyId, recipient);
      }
    }
    return this.requestSpend(req);
  }

  /**
   * owner only: add a recipient to the policy allowlist (union with the
   * existing entries). used by guardedSpend({ autoAllowApproved }) so a
   * human-approved warn can actually complete on-chain.
   */
  async addAllowedRecipient(policyId: string, recipient: string): Promise<void> {
    const policy = await this.getPolicy(policyId);
    const current: string[] = policy.allowed_recipients ?? [];
    const next = [...new Set([...current, recipient.trim().toLowerCase()])];
    await this.account.signAndSendTransaction({
      receiverId: this.cfg.contractId,
      actions: [
        najActions.functionCall(
          "set_allowed_recipients",
          { policy_id: policyId, recipients: next },
          BigInt(100) * TGAS,
          0n,
        ),
      ],
    });
  }

  /**
   * the hot path. sends the RLP-encoded spend request; returns the verdict.
   * on deny the contract panicked — we surface the SHEARPIN_* reason.
   * on allow the mpc signature is requested through the contract's own
   * promise chain; outcome carries the near tx hash + logs.
   */
  async requestSpend(req: SpendRequest): Promise<SpendOutcome> {
    try {
      const out = await this.account.signAndSendTransaction({
        receiverId: this.cfg.contractId,
        actions: [
          najActions.functionCall(
            "request_signature",
            {
              policy_id: req.policyId,
              derivation_path: req.derivationPath,
              key_type: req.keyType,
              payload: Array.from(req.payload),
            },
            BigInt(300) * TGAS,
            0n // MUST be 0: function-call keys cannot attach ANY deposit
               // (protocol rejects it — DepositWithFunctionCall). the
               // contract pays the MPC forwarding deposit from its balance.
          ),
        ],
      }) as unknown as {
        transaction: { hash: string };
        transaction_outcome?: { outcome?: { logs?: string[] } };
        receipts_outcome?: { outcome?: { logs?: string[] } }[];
        status?: { SuccessValue?: string | null };
      };
      const logs: string[] = [];
      logs.push(...(out.transaction_outcome?.outcome?.logs ?? []));
      for (const r of out.receipts_outcome ?? []) {
        logs.push(...(r.outcome?.logs ?? []));
      }
      // persist-deny paths SUCCEED and return a SHEARPIN_* string as value
      const succ = out.status?.SuccessValue;
      if (succ) {
        let retVal = "";
        try { retVal = Buffer.from(succ, "base64").toString("utf8"); } catch { /* not utf8 */ }
        if (retVal.includes("SHEARPIN_")) {
          return { verdict: "deny", reason: retVal.match(/SHEARPIN_[A-Z_]+/)?.[0] ?? retVal, logs };
        }
      }
      return { verdict: "allow", nearTxHash: out.transaction.hash, logs };
    } catch (err) {
      // the contract panics on deny; near-api-js throws. dig the
      // SHEARPIN_* reason and the deny log out of the error.
      const e = err as { message?: string; transactionResult?: { receipts_outcome?: { outcome?: { logs?: string[]; status?: unknown } }[] } };
      const msg = e.message ?? "";
      const logs: string[] = [];
      for (const r of e.transactionResult?.receipts_outcome ?? []) {
        logs.push(...(r.outcome?.logs ?? []));
      }
      const m = msg.match(/SHEARPIN_[A-Z_]+[^\n"']*/);
      const denyLog = logs.map((l) => l.match(/{"event":"deny","policy":"[^"]*","reason":"([a-z_]+)"/)).find(Boolean);
      if (m) return { verdict: "deny", reason: m[0].trim(), logs };
      if (denyLog) {
        const reason = denyLog[1];
        const shearpin = reason === "over_tx_snap" ? "SHEARPIN_OVER_TX"
          : reason === "over_daily_snap" ? "SHEARPIN_OVER_DAILY"
          : reason === "tripped" ? "SHEARPIN_TRIPPED"
          : reason === "frozen" ? "SHEARPIN_FROZEN"
          : reason === "cooldown" ? "SHEARPIN_COOLDOWN"
          : reason === "rate" ? "SHEARPIN_RATE"
          : reason === "chain_not_allowed" ? "SHEARPIN_CHAIN"
          : reason === "legacy_tx_rejected" ? "SHEARPIN_LEGACY_TX"
          : `SHEARPIN_${reason.toUpperCase()}`;
        return { verdict: "deny", reason: `${shearpin}: ${reason}`, logs };
      }
      throw err;
    }
  }

  /** owner-only: set allowed recipients for a policy (fail-closed: empty = deny all) */
  async setAllowedRecipients(policyId: string, recipients: string[]): Promise<PolicyView> {
    await this.account.signAndSendTransaction({
      receiverId: this.cfg.contractId,
      actions: [
        najActions.functionCall(
          "set_allowed_recipients",
          { policy_id: policyId, recipients },
          BigInt(100) * TGAS,
          0n
        ),
      ],
    });
    return this.getPolicy(policyId);
  }

  /** owner-only: set allowed chain IDs (fail-closed: empty = deny all chains) */
  async setAllowedChainIds(policyId: string, chainIds: number[]): Promise<PolicyView> {
    await this.account.signAndSendTransaction({
      receiverId: this.cfg.contractId,
      actions: [
        najActions.functionCall(
          "set_allowed_chain_ids",
          { policy_id: policyId, chain_ids: chainIds },
          BigInt(100) * TGAS,
          0n
        ),
      ],
    });
    return this.getPolicy(policyId);
  }

  // ------------------------------------------------------------------
  // RLP encoding (EIP-155)
  // ------------------------------------------------------------------

  /** encode a bigint as canonical RLP integer item */
  private static encodeInt(v: bigint): Uint8Array {
    if (v === 0n) return new Uint8Array([0x80]);
    const bytes: number[] = [];
    let x = v;
    while (x > 0n) {
      bytes.unshift(Number(x & 0xffn));
      x >>= 8n;
    }
    if (bytes[0] === 0) throw new Error("leading zero in int encoding");
    if (bytes.length === 1 && bytes[0] <= 0x7f) return new Uint8Array(bytes);
    const out = new Uint8Array(1 + bytes.length);
    out[0] = 0x80 + bytes.length;
    out.set(bytes, 1);
    return out;
  }

  /** encode a byte string as RLP item (handles >55-byte long-form prefix) */
  private static encodeBytes(data: Uint8Array): Uint8Array {
    if (data.length === 0) return new Uint8Array([0x80]);
    if (data.length === 1 && data[0] <= 0x7f) return data;
    if (data.length <= 55) {
      const out = new Uint8Array(1 + data.length);
      out[0] = 0x80 + data.length;
      out.set(data, 1);
      return out;
    }
    // long-form: 0xb7 + len-of-len, then length bytes, then payload
    const lenBytes: number[] = [];
    let l = data.length;
    while (l > 0) {
      lenBytes.unshift(l & 0xff);
      l >>= 8;
    }
    const out = new Uint8Array(1 + lenBytes.length + data.length);
    out[0] = 0xb7 + lenBytes.length;
    out.set(lenBytes, 1);
    out.set(data, 1 + lenBytes.length);
    return out;
  }

  private static encodeList(inner: Uint8Array): Uint8Array {
    const len = inner.length;
    if (len <= 55) {
      const out = new Uint8Array(1 + len);
      out[0] = 0xc0 + len;
      out.set(inner, 1);
      return out;
    }
    const lenBytes: number[] = [];
    let l = len;
    while (l > 0) {
      lenBytes.unshift(l & 0xff);
      l >>= 8;
    }
    const out = new Uint8Array(1 + lenBytes.length + len);
    out[0] = 0xf7 + lenBytes.length;
    out.set(lenBytes, 1);
    out.set(inner, 1 + lenBytes.length);
    return out;
  }

  /**
   * build an RLP-encoded unsigned EIP-155 EVM tx (9 fields).
   * native transfer: data empty. ERC-20: use buildErc20TransferRlp instead.
   */
  static buildEip155TransferRlp(opts: {
    to: string;
    value: bigint;
    chainId: bigint;
    nonce?: bigint;
    gasPrice?: bigint;
    gasLimit?: bigint;
    data?: Uint8Array;
  }): Uint8Array {
    const to = opts.to.startsWith("0x") ? opts.to.slice(2) : opts.to;
    if (to.length !== 40) throw new Error("to must be 20-byte hex address");
    const toBytes = Buffer.from(to, "hex");
    if (toBytes.length !== 20) throw new Error("to must be 20 bytes");

    const nonce = opts.nonce ?? 1n;
    const gasPrice = opts.gasPrice ?? 20_000_000_000n; // 20 gwei
    const gasLimit = opts.gasLimit ?? 21_000n;
    const data = opts.data ?? new Uint8Array(0);

    if (opts.chainId <= 0n) throw new Error("chainId required (EIP-155 replay protection)");

    const items: Uint8Array[] = [
      ShearPinClient.encodeInt(nonce),
      ShearPinClient.encodeInt(gasPrice),
      ShearPinClient.encodeInt(gasLimit),
      (() => {
        const out = new Uint8Array(1 + 20);
        out[0] = 0x94;
        out.set(toBytes, 1);
        return out;
      })(),
      ShearPinClient.encodeInt(opts.value),
      ShearPinClient.encodeBytes(data),
      ShearPinClient.encodeInt(opts.chainId),
      ShearPinClient.encodeInt(0n),
      ShearPinClient.encodeInt(0n),
    ];

    return ShearPinClient.encodeList(Buffer.concat(items));
  }

  /** ERC-20 transfer calldata: selector + to(32) + amount(32) */
  static encodeErc20TransferCalldata(to: string, amount: bigint): Uint8Array {
    const toHex = to.startsWith("0x") ? to.slice(2) : to;
    if (toHex.length !== 40) throw new Error("recipient must be 20-byte hex");
    const out = new Uint8Array(68);
    out.set([0xa9, 0x05, 0x9c, 0xbb], 0); // transfer(address,uint256)
    out.set(Buffer.from(toHex, "hex"), 16); // right-aligned in 32-byte word
    // amount: 32-byte big-endian word
    const amt = new Uint8Array(32);
    let v = amount;
    for (let i = 31; i >= 0; i--) {
      amt[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    out.set(amt, 36);
    return out;
  }

  /**
   * build an RLP-encoded unsigned EIP-155 ERC-20 transfer tx.
   * the token contract is `to`, value=0, calldata transfers `amount` of
   * token to `recipient`. the contract decodes recipient+amount from
   * calldata and applies the recipient allowlist + caps to them.
   */
  static buildErc20TransferRlp(opts: {
    token: string;
    recipient: string;
    amount: bigint;
    chainId: bigint;
    nonce?: bigint;
    gasPrice?: bigint;
    gasLimit?: bigint;
  }): Uint8Array {
    const calldata = ShearPinClient.encodeErc20TransferCalldata(opts.recipient, opts.amount);
    return ShearPinClient.buildEip155TransferRlp({
      to: opts.token,
      value: 0n,
      chainId: opts.chainId,
      nonce: opts.nonce,
      gasPrice: opts.gasPrice,
      gasLimit: opts.gasLimit ?? 60_000n,
      data: calldata,
    });
  }

  /** @deprecated use buildEip155TransferRlp (EIP-155, replay-protected) */
  static buildLegacyTransferRlp(opts: {
    to: string;
    value: bigint;
    nonce?: bigint;
    gasPrice?: bigint;
    gasLimit?: bigint;
    data?: Uint8Array;
  }): Uint8Array {
    return ShearPinClient.buildEip155TransferRlp({ ...opts, chainId: 11155111n });
  }
}

/** broadcast an mpc-signed evm tx to a target chain */
export async function broadcastEvm(rpcUrl: string, rawTx: string): Promise<string> {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const res = await provider.broadcastTransaction(rawTx);
  return res.hash;
}

/** hash of an unsigned eip-1559 tx for mpc signing (alt path) */
export function hashForEvmTx(opts: {
  nonce: bigint;
  to: string;
  value: bigint;
  data: string;
  chainId: bigint;
  gasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}): Uint8Array {
  const tx = ethers.Transaction.from({
    to: opts.to,
    value: opts.value,
    nonce: Number(opts.nonce),
    data: opts.data === "0x" ? "0x" : opts.data,
    chainId: Number(opts.chainId),
    gasLimit: opts.gasLimit,
    maxFeePerGas: opts.maxFeePerGas,
    maxPriorityFeePerGas: opts.maxPriorityFeePerGas,
    type: 2,
  });
  return ethers.getBytes(tx.unsignedHash);
}

export { ethers };