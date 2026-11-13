/**
 * guardedSpend wiring tests: the wrapper must consult the ENRICHED verdict
 * (contract verdict + off-chain signals) when enrich opts are passed, and
 * keep the current behavior when they are not. run against a stub `this`
 * — the real method body is exercised, no NEAR network needed.
 */
import { describe, it, expect } from "vitest";
import { ShearPinClient } from "./index.js";
import type { SpendRequest } from "./index.js";

const NOW = 1_700_000_000_000;
const REC = "0xrec";
const req: SpendRequest = {
  policyId: "sat1",
  derivationPath: "eth/0",
  keyType: "ecdsa",
  payload: new Uint8Array(),
};

function makeFetch() {
  const youngTs = Math.floor((NOW - 2 * 86_400_000) / 1000);
  const tx = (rows: unknown[]) =>
    new Response(JSON.stringify({ status: "1", message: "OK", result: rows }), {
      headers: { "content-type": "application/json" },
    });
  return async (input: string | URL | Request): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.includes("etherscan")) {
      return tx(url.includes("sort=asc") ? [{ timeStamp: String(youngTs) }] : [{ hash: "0x1" }]);
    }
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x" }));
  };
}

function stubThis(base: { verdict: "allow" | "warn" | "block"; reasons?: string[] }) {
  let spendCalls = 0;
  return {
    checkCounterparty: async () => ({ verdict: base.verdict, reasons: base.reasons ?? [] }),
    requestSpend: async () => {
      spendCalls++;
      return { verdict: "allow" as const };
    },
    spendCalls: () => spendCalls,
  };
}

describe("guardedSpend with signal enrichment", () => {
  it("asks the human when enrichment upgrades allow to warn", async () => {
    const stub = stubThis({ verdict: "allow" });
    const warnReasons: string[][] = [];
    const out = await ShearPinClient.prototype.guardedSpend.call(
      stub as never,
      req,
      REC,
      async (reasons) => {
        warnReasons.push(reasons);
        return false; // human says no
      },
      { enrich: { etherscanApiKey: "K", evmRpcUrl: "http://rpc", fetchFn: makeFetch(), now: () => NOW } },
    );
    expect(out).toMatchObject({ kind: "refused", verdict: "warn" });
    expect(warnReasons.join(" ")).toMatch(/days old/); // enriched reason reached the human
    expect(stub.spendCalls()).toBe(0); // nothing was submitted
  });

  it("proceeds to requestSpend when enrichment keeps allow", async () => {
    const stub = stubThis({ verdict: "allow" });
    let warned = 0;
    const oldTs = Math.floor((NOW - 400 * 86_400_000) / 1000);
    const fetchFn = async (input: string | URL | Request): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const rows = url.includes("sort=asc") ? [{ timeStamp: String(oldTs) }] : Array.from({ length: 50 }, (_, i) => ({ hash: `0x${i}` }));
      return new Response(JSON.stringify({ status: "1", message: "OK", result: rows }));
    };
    const out = await ShearPinClient.prototype.guardedSpend.call(
      stub as never,
      req,
      REC,
      async () => {
        warned++;
        return true;
      },
      { enrich: { etherscanApiKey: "K", evmRpcUrl: "http://rpc", fetchFn, now: () => NOW } },
    );
    expect(out).toMatchObject({ verdict: "allow" });
    expect(warned).toBe(0);
    expect(stub.spendCalls()).toBe(1);
  });

  it("without enrich opts keeps the current contract-only behavior", async () => {
    const stub = stubThis({ verdict: "allow" });
    let warned = 0;
    const out = await ShearPinClient.prototype.guardedSpend.call(stub as never, req, REC, async () => {
      warned++;
      return true;
    });
    expect(out).toMatchObject({ verdict: "allow" });
    expect(warned).toBe(0);
    expect(stub.spendCalls()).toBe(1);
  });
});

describe("reportCounterparty attaches the anti-Sybil stake", () => {
  it("sends the 0.01 NEAR REPORT_DEPOSIT the contract now requires", async () => {
    let captured: { actions: Array<{ deposit: bigint }> } | null = null;
    const stub = {
      cfg: { contractId: "test.near" },
      account: {
        signAndSendTransaction: async (args: never) => {
          captured = args as never;
          return {};
        },
      },
    };
    await ShearPinClient.prototype.reportCounterparty.call(
      stub as never,
      "0xabc0000000000000000000000000000000000000",
      "drainer",
      "https://evidence.example/1",
    );
    const action = (captured as never as { actions: Array<{ functionCall: { deposit: bigint } }> }).actions[0].functionCall;
    expect(action.deposit).toBe(10n ** 22n); // REPORT_DEPOSIT
  });
});

/** FC-key agent stub: warns on unvetted recipients, captures owner-method attempts */
function warnStub() {
  let spendCalls = 0;
  const txs: Array<{ method: string; args: Record<string, unknown> }> = [];
  return {
    spendCalls: () => spendCalls,
    txs,
    cfg: { contractId: "test.near" },
    addAllowedRecipient: ShearPinClient.prototype.addAllowedRecipient,
    checkCounterparty: async () => ({
      verdict: "warn" as const,
      reasons: ["not in the policy recipient allowlist (unvetted)"],
    }),
    getPolicy: async () => ({ allowed_recipients: ["0xd4e56740f876afec8011e179a8b763074e6b5c8f"] }),
    requestSpend: async () => {
      spendCalls++;
      return { verdict: "allow" as const };
    },
    account: {
      signAndSendTransaction: async (args: {
        actions: Array<{ functionCall: { methodName: string; args: Record<string, unknown> } }>;
      }) => {
        const fc = args.actions[0].functionCall;
        // near-api-js serializes args to bytes immediately — decode back
        const raw = fc.args as unknown;
        const decoded =
          raw instanceof Uint8Array
            ? (JSON.parse(Buffer.from(raw).toString("utf8")) as Record<string, unknown>)
            : (raw as Record<string, unknown>);
          txs.push({ method: fc.methodName, args: decoded });
          return {};
        },
      },
    };
  }

describe("guardedSpend closes the loop on human-approved warn (solution A)", () => {
  it("autoAllowApproved: adds the approved recipient to the allowlist before spending", async () => {
    const stub = warnStub();
    const out = await ShearPinClient.prototype.guardedSpend.call(
      stub as never,
      req,
      "0xnew000000000000000000000000000000000000",
      async () => true, // the human approves
      { autoAllowApproved: true, ownerClient: stub as never },
    );
    expect(out).toMatchObject({ verdict: "allow" });
    expect(stub.spendCalls()).toBe(1);
    const call = stub.txs.find((t) => t.method === "set_allowed_recipients");
    expect(call).toBeTruthy();
    expect((call!.args.recipients as string[]).map((r) => r.toLowerCase())).toContain(
      "0xnew000000000000000000000000000000000000",
    );
    // the existing vendor entry survives (union, not replace)
    expect((call!.args.recipients as string[]).length).toBe(2);
  });

  it("without autoAllowApproved an approved warn still proceeds (old behavior)", async () => {
    const stub = warnStub();
    const out = await ShearPinClient.prototype.guardedSpend.call(
      stub as never,
      req,
      "0xnew000000000000000000000000000000000000",
      async () => true,
    );
    expect(out).toMatchObject({ verdict: "allow" });
    expect(stub.txs.find((t) => t.method === "set_allowed_recipients")).toBeUndefined();
  });

  it("a refused warn never touches the allowlist", async () => {
    const stub = warnStub();
    const out = await ShearPinClient.prototype.guardedSpend.call(
      stub as never,
      req,
      "0xnew000000000000000000000000000000000000",
      async () => false, // the human declines
      { autoAllowApproved: true },
    );
    expect(out).toMatchObject({ kind: "refused", verdict: "warn" });
    expect(stub.spendCalls()).toBe(0);
    expect(stub.txs.find((t) => t.method === "set_allowed_recipients")).toBeUndefined();
  });
});

describe("checkCounterparty normalizes the contract tuple", () => {
  it("maps the contract's [verdict, reasons] tuple to { verdict, reasons }", async () => {
    const stub = {
      callView: async () => ["warn", ["not in the policy recipient allowlist (unvetted)"]],
    };
    const out = await ShearPinClient.prototype.checkCounterparty.call(stub as never, "sat1", "0xabc");
    expect(out).toEqual({ verdict: "warn", reasons: ["not in the policy recipient allowlist (unvetted)"] });
  });

  it("passes through an already-normalized object", async () => {
    const stub = {
      callView: async () => ({ verdict: "block", reasons: ["reported"] }),
    };
    const out = await ShearPinClient.prototype.checkCounterparty.call(stub as never, "sat1", "0xabc");
    expect(out).toEqual({ verdict: "block", reasons: ["reported"] });
  });
});

describe("role separation: the agent key must never sign an owner write", () => {
  it("autoAllowApproved uses ownerClient for the allowlisting, not the agent client", async () => {
    const stub = warnStub(); // agent-side: FC-key client
    let ownerVets = 0;
    const ownerClient = {
      addAllowedRecipient: async (_policyId: string, recipient: string) => {
        ownerVets++;
        return recipient;
      },
    };
    const out = await ShearPinClient.prototype.guardedSpend.call(
      stub as never,
      req,
      "0xnew000000000000000000000000000000000000",
      async () => true, // human approves
      { autoAllowApproved: true, ownerClient: ownerClient as never },
    );
    expect(out).toMatchObject({ verdict: "allow" });
    expect(stub.spendCalls()).toBe(1); // agent submitted the spend
    expect(ownerVets).toBe(1); // owner signed the vetting
    // the agent client itself never touched set_allowed_recipients —
    // its FC key couldn't anyway (methods: request_signature only)
    expect(stub.txs.find((t) => t.method === "set_allowed_recipients")).toBeUndefined();
  });
});

describe("requestSpend is function-call-key compatible", () => {
  it("attaches ZERO deposit — the protocol rejects any deposit on an FC-key call", async () => {
    let captured: { actions: Array<{ functionCall: { deposit: bigint; methodName: string } }> } | null = null;
    const stub = {
      cfg: { contractId: "test.near" },
      account: {
        signAndSendTransaction: async (args: never) => {
          captured = args as never;
          return {
            transaction: { hash: "0x1" },
            transaction_outcome: { outcome: { logs: [] } },
            receipts_outcome: [],
            status: { SuccessValue: null },
          };
        },
      },
    };
    await ShearPinClient.prototype.requestSpend.call(stub as never, {
      policyId: "sat1",
      derivationPath: "eth/0",
      keyType: "ecdsa",
      payload: new Uint8Array([1, 2, 3]),
    });
    const action = (captured as never as { actions: Array<{ functionCall: { deposit: bigint; methodName: string } }> }).actions[0].functionCall;
    expect(action.methodName).toBe("request_signature");
    expect(action.deposit).toBe(0n); // DepositWithFunctionCall otherwise
  });
});

describe("autoAllowApproved without ownerClient fails loudly", () => {
  it("throws 'autoAllowApproved requires ownerClient' instead of burning the agent key", async () => {
    const stub = warnStub();
    await expect(
      ShearPinClient.prototype.guardedSpend.call(
        stub as never,
        req,
        "0xnew000000000000000000000000000000000000",
        async () => true,
        { autoAllowApproved: true }, // no ownerClient
      ),
    ).rejects.toThrow("autoAllowApproved requires ownerClient");
    expect(stub.spendCalls()).toBe(0);
  });
});
