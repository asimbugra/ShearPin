/**
 * shearpin sdk — the agent only ever asks.
 *
 * flow: build RLP-encoded unsigned legacy EVM tx -> contract parses it on-chain
 * to derive amount + recipient -> contract checks policy -> if allowed, the
 * contract itself requests the mpc signature -> we relay the signed tx
 * to the destination chain. denials panic inside the contract with a
 * SHEARPIN_* reason and never reach the mpc network at all.
 *
 * CRITICAL SECURITY: the agent NEVER claims an amount. the contract parses
 * the RLP payload and extracts value (amount) and to (recipient) itself.
 * an agent cannot declare "1" while signing a 100 ETH transfer.
 */
import { JsonRpcProvider } from "@near-js/providers";
import { KeyPairSigner } from "@near-js/signers";
import { Account, JsonRpcProvider as NajProvider, KeyPairSigner as NajKeyPairSigner, actions as najActions } from "near-api-js";
import { ethers } from "ethers";

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
}

/** RLP-encoded unsigned legacy EVM transaction (agent submits this, contract parses it) */
export interface SpendRequest {
  policyId: string;
  /** sub-path under the policy namespace, e.g. "eth/0" */
  derivationPath: string;
  keyType: KeyType;
  /** RLP-encoded unsigned legacy tx: [nonce, gasPrice, gasLimit, to, value, data] */
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
            1n
          ),
        ],
      }) as unknown as {
        transaction: { hash: string };
        transaction_outcome?: { outcome?: { logs?: string[] } };
        receipts_outcome?: { outcome?: { logs?: string[] } }[];
      };
      const logs: string[] = [];
      logs.push(...(out.transaction_outcome?.outcome?.logs ?? []));
      for (const r of out.receipts_outcome ?? []) {
        logs.push(...(r.outcome?.logs ?? []));
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
          : `SHEARPIN_${reason.toUpperCase()}`;
        return { verdict: "deny", reason: `${shearpin}: ${reason}`, logs };
      }
      throw err;
    }
  }

  /** owner-only: set allowed recipients for a policy (fail-closed: empty = deny all) */
  async setAllowedRecipients(policyId: string, recipients: string[]): Promise<PolicyView> {
    const out = await this.account.signAndSendTransaction({
      receiverId: this.cfg.contractId,
      actions: [
        najActions.functionCall(
          "set_allowed_recipients",
          { policy_id: policyId, recipients },
          BigInt(100) * TGAS,
          0n
        ),
      ],
    }) as unknown as { transaction: { hash: string }; transaction_outcome?: { outcome?: { logs?: string[] } } };
    // re-fetch to get updated view
    return this.getPolicy(policyId);
  }

  /** build an RLP-encoded unsigned legacy EVM transfer tx */
  static buildLegacyTransferRlp(opts: {
    to: string;
    value: bigint;
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

    const encodeInt = (v: bigint): Uint8Array => {
      if (v === 0n) return new Uint8Array([0x80]);
      const bytes: number[] = [];
      let x = v;
      while (x > 0n) {
        bytes.unshift(Number(x & 0xffn));
        x >>= 8n;
      }
      // canonical RLP: no leading zeros
      if (bytes[0] === 0) throw new Error("leading zero in int encoding");
      const prefix = bytes.length === 1 && bytes[0] <= 0x7f ? 0 : 0x80 + bytes.length;
      const out = new Uint8Array(1 + bytes.length);
      out[0] = prefix;
      out.set(bytes, 1);
      return out;
    };

    // RLP items: nonce, gasPrice, gasLimit, to, value, data
    const items: Uint8Array[] = [
      encodeInt(nonce),
      encodeInt(gasPrice),
      encodeInt(gasLimit),
      // to address: 20 bytes string
      (() => {
        const out = new Uint8Array(1 + 20);
        out[0] = 0x94; // 20-byte string prefix
        out.set(toBytes, 1);
        return out;
      })(),
      encodeInt(opts.value),
      // data
      data.length === 0 ? new Uint8Array([0x80]) : (() => {
        const out = new Uint8Array(1 + data.length);
        out[0] = 0x80 + data.length;
        out.set(data, 1);
        return out;
      })(),
    ];

    // concatenate all items
    const inner = Buffer.concat(items);

    // outer list prefix
    const len = inner.length;
    let outerPrefix: Uint8Array;
    if (len <= 55) {
      outerPrefix = new Uint8Array([0xc0 + len]);
    } else {
      const lenBytes: number[] = [];
      let l = len;
      while (l > 0) {
        lenBytes.unshift(l & 0xff);
        l >>= 8;
      }
      outerPrefix = new Uint8Array([0xf7 + lenBytes.length, ...lenBytes]);
    }

    return new Uint8Array(Buffer.concat([outerPrefix, inner]));
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