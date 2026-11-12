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
