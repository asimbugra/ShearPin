/**
 * tests for the off-chain counterparty signal enrichment layer.
 * all network access goes through an injectable fetchFn — no live
 * calls in unit tests. base verdicts come from a stub client.
 */
import { describe, it, expect } from "vitest";
import { enrichCounterparty } from "./signals.js";
import type { CodeStore } from "./signals.js";

const NOW = 1_700_000_000_000; // fixed clock: 2023-11-14T22:13:20Z
const DAY_MS = 86_400_000;

/** a json Response helper */
function jsonRes(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json" },
  });
}

/** etherscan txlist response builder */
function txlist(rows: Array<Record<string, unknown>>) {
  return { status: "1", message: "OK", result: rows };
}

interface Route {
  match: (url: string) => boolean;
  body: unknown;
  throw?: Error;
}

/** build a fetchFn from url-matched routes; unmatched urls -> throw */
function makeFetch(routes: Route[]): typeof fetch {
  return async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    for (const r of routes) {
      if (r.match(url)) {
        if (r.throw) throw r.throw;
        return jsonRes(r.body);
      }
    }
    throw new Error(`no route for ${url}`);
  };
}

const isEtherscan = (u: string) => u.includes("etherscan");
const isRpc = (u: string) => !u.includes("etherscan");
/** which address a txlist url queries */
const queried = (u: string) => u.match(/address=([^&]+)/)?.[1]?.toLowerCase() ?? "";
const isAsc = (u: string) => u.includes("sort=asc");
const isDesc = (u: string) => u.includes("sort=desc");

/** etherscan v2 query builder mirrors what the module must produce */
const etherscanUrl = (addr: string, sort: "asc" | "desc") =>
  `https://api.etherscan.io/v2/api?chainid=11155111&module=account&action=txlist&address=${addr}&page=1&sort=${sort}`;

/** standard base client stub */
function stubClient(verdict: "allow" | "warn" | "block", reasons: string[] = []) {
  return {
    checkCounterparty: async (_policyId: string, _address: string) => ({ verdict, reasons }),
  };
}

function memStore(preset: Record<string, string> = {}): CodeStore & { dump(): Record<string, string> } {
  const m = new Map(Object.entries(preset));
  return {
    get: (a) => m.get(a.toLowerCase()) ?? null,
    set: (a, h) => void m.set(a.toLowerCase(), h),
    dump: () => Object.fromEntries(m),
  };
}

describe("enrichCounterparty", () => {
  it("keeps allow for an old, active EOA receiver", async () => {
    const REC = "0xaaa";
    const oldTs = Math.floor((NOW - 400 * DAY_MS) / 1000);
    const fetchFn = makeFetch([
      {
        match: (u) => isEtherscan(u) && isAsc(u) && queried(u) === REC,
        body: txlist([{ timeStamp: String(oldTs) }]),
      },
      {
        match: (u) => isEtherscan(u) && isDesc(u) && queried(u) === REC,
        body: txlist(Array.from({ length: 50 }, (_, i) => ({ hash: `0x${i}` }))),
      },
      { match: isRpc, body: { jsonrpc: "2.0", id: 1, result: "0x" } }, // EOA
    ]);
    const out = await enrichCounterparty(stubClient("allow"), "sat1", REC, {
      etherscanApiKey: "K",
      evmRpcUrl: "http://rpc",
      fetchFn,
      now: () => NOW,
    });
    expect(out.verdict).toBe("allow");
    expect(out.signals.map((s) => s.risk)).toEqual([false, false, false]);
  });

  it("upgrades allow to warn when the receiver account is young", async () => {
    const REC = "0xbbb";
    const youngTs = Math.floor((NOW - 2 * DAY_MS) / 1000);
    const fetchFn = makeFetch([
      {
        match: (u) => isEtherscan(u) && isAsc(u) && queried(u) === REC,
        body: txlist([{ timeStamp: String(youngTs) }]),
      },
      { match: (u) => isEtherscan(u) && isDesc(u) && queried(u) === REC, body: txlist([{ hash: "0x1" }]) },
      { match: isRpc, body: { jsonrpc: "2.0", id: 1, result: "0x" } },
    ]);
    const out = await enrichCounterparty(stubClient("allow"), "sat1", REC, {
      etherscanApiKey: "K",
      evmRpcUrl: "http://rpc",
      fetchFn,
      now: () => NOW,
    });
    expect(out.verdict).toBe("warn");
    expect(out.reasons.join(" ")).toMatch(/days old/);
    expect(out.signals.find((s) => s.name === "account-age")?.risk).toBe(true);
  });

  it("warns on very low recent activity even for an old account", async () => {
    const REC = "0xccc";
    const oldTs = Math.floor((NOW - 400 * DAY_MS) / 1000);
    const fetchFn = makeFetch([
      {
        match: (u) => isEtherscan(u) && isAsc(u) && queried(u) === REC,
        body: txlist([{ timeStamp: String(oldTs) }]),
      },
      { match: (u) => isEtherscan(u) && isDesc(u) && queried(u) === REC, body: txlist([{ hash: "0x1" }]) },
      { match: isRpc, body: { jsonrpc: "2.0", id: 1, result: "0x" } },
    ]);
    const out = await enrichCounterparty(stubClient("allow"), "sat1", REC, {
      etherscanApiKey: "K",
      evmRpcUrl: "http://rpc",
      fetchFn,
      now: () => NOW,
    });
    expect(out.verdict).toBe("warn");
    expect(out.reasons.join(" ")).toMatch(/low activity/);
  });

  it("warns when observed contract code changed since last check", async () => {
    const store = memStore({ "0xddd": "0xoldhash" });
    const fetchFn = makeFetch([
      { match: isRpc, body: { jsonrpc: "2.0", id: 1, result: "0x6080604052feed" } },
    ]);
    const out = await enrichCounterparty(stubClient("allow"), "sat1", "0xddd", {
      etherscanApiKey: "K",
      evmRpcUrl: "http://rpc",
      codeStore: store,
      fetchFn,
      now: () => NOW,
    });
    expect(out.verdict).toBe("warn");
    expect(out.reasons.join(" ")).toMatch(/code changed/);
    expect(out.signals.find((s) => s.name === "contract")?.risk).toBe(true);
  });

  it("records a first-seen contract without upgrading the verdict", async () => {
    const store = memStore();
    const fetchFn = makeFetch([
      { match: isRpc, body: { jsonrpc: "2.0", id: 1, result: "0xdeadbeef" } },
    ]);
    const out = await enrichCounterparty(stubClient("allow"), "sat1", "0xeee", {
      etherscanApiKey: "K",
      evmRpcUrl: "http://rpc",
      codeStore: store,
      fetchFn,
      now: () => NOW,
    });
    expect(out.verdict).toBe("allow");
    expect(store.dump()["0xeee"]).toBeTruthy(); // code hash recorded
  });

  it("notes prior successful interactions with this agent", async () => {
    const REC = "0xrec1234567890123456789012345678901234";
    const fetchFn = makeFetch([
      {
        match: (u) => isEtherscan(u) && isAsc(u) && queried(u) === REC,
        body: txlist([]),
      },
      {
        match: (u) => isEtherscan(u) && isDesc(u) && queried(u) === REC,
        body: txlist([{ hash: "0x1" }]),
      },
      {
        match: (u) => isEtherscan(u) && isDesc(u) && queried(u) === "0xagent",
        body: txlist([{ to: REC, isError: "0" }, { to: "0xother", isError: "0" }, { to: REC, isError: "1" }]),
      },
      { match: isRpc, body: { jsonrpc: "2.0", id: 1, result: "0x" } },
    ]);
    const out = await enrichCounterparty(stubClient("warn", ["1 report"]), "sat1", REC, {
      etherscanApiKey: "K",
      evmRpcUrl: "http://rpc",
      agentEoa: "0xagent",
      fetchFn,
      now: () => NOW,
    });
    const prior = out.signals.find((s) => s.name === "prior-interactions");
    expect(prior?.value).toMatch(/1 prior successful/);
    expect(prior?.risk).toBe(false);
    expect(out.verdict).toBe("warn"); // unchanged by a positive note
  });

  it("keeps block even when risk signals fire", async () => {
    const youngTs = Math.floor((NOW - 1 * DAY_MS) / 1000);
    const fetchFn = makeFetch([
      {
        match: (u) => isEtherscan(u) && isAsc(u),
        body: txlist([{ timeStamp: String(youngTs) }]),
      },
      { match: (u) => isEtherscan(u) && isDesc(u), body: txlist([]) },
      { match: isRpc, body: { jsonrpc: "2.0", id: 1, result: "0x" } },
    ]);
    const out = await enrichCounterparty(stubClient("block", ["reported as drainer"]), "sat1", "0xfff", {
      etherscanApiKey: "K",
      evmRpcUrl: "http://rpc",
      fetchFn,
      now: () => NOW,
    });
    expect(out.verdict).toBe("block");
    expect(out.reasons.join(" ")).toMatch(/drainer/);
  });

  it("degrades gracefully when the etherscan call fails", async () => {
    const fetchFn = makeFetch([
      { match: isEtherscan, body: {}, throw: new Error("boom") },
      { match: isRpc, body: { jsonrpc: "2.0", id: 1, result: "0x" } },
    ]);
    const out = await enrichCounterparty(stubClient("allow"), "sat1", "0x123", {
      etherscanApiKey: "K",
      evmRpcUrl: "http://rpc",
      fetchFn,
      now: () => NOW,
    });
    expect(out.verdict).toBe("allow");
    expect(out.reasons.join(" ")).toMatch(/signal unavailable: account-age/);
    expect(out.signals.find((s) => s.name === "contract")?.value).toMatch(/EOA/); // rpc still works
  });

  it("degrades gracefully when the rpc returns a malformed code value", async () => {
    const fetchFn = makeFetch([
      { match: isEtherscan, body: {}, throw: new Error("boom") },
      { match: isRpc, body: { jsonrpc: "2.0", id: 1, result: [{ hash: "0x0" }] } }, // garbage
    ]);
    const out = await enrichCounterparty(stubClient("allow"), "sat1", "0x334", {
      etherscanApiKey: "K",
      evmRpcUrl: "http://rpc",
      fetchFn,
      now: () => NOW,
    });
    expect(out.verdict).toBe("allow"); // a broken rpc must never break the flow
    expect(out.reasons.join(" ")).toMatch(/signal unavailable: contract/);
  });

  it("degrades gracefully when no api key is configured", async () => {
    const fetchFn = makeFetch([
      { match: isRpc, body: { jsonrpc: "2.0", id: 1, result: "0x" } },
    ]);
    const out = await enrichCounterparty(stubClient("allow"), "sat1", "0x223", {
      fetchFn,
      now: () => NOW,
    });
    expect(out.verdict).toBe("allow");
    expect(out.reasons.join(" ")).toMatch(/signal unavailable: account-age/);
    expect(out.reasons.join(" ")).toMatch(/signal unavailable: prior-interactions/);
  });

  it("failClosed: unreachable signals upgrade allow to warn", async () => {
    const fetchFn = makeFetch([
      { match: isEtherscan, body: {}, throw: new Error("boom") },
      { match: isRpc, body: { jsonrpc: "2.0", id: 1, result: "0x" } },
    ]);
    const out = await enrichCounterparty(stubClient("allow"), "sat1", "0x334", {
      etherscanApiKey: "K",
      evmRpcUrl: "http://rpc",
      fetchFn,
      now: () => NOW,
      failClosed: true,
    });
    expect(out.verdict).toBe("warn"); // unreachable != risk-free
    expect(out.reasons.join(" ")).toMatch(/fail-closed/);
  });

  it("failClosed keeps block when signals are unavailable", async () => {
    const out = await enrichCounterparty(stubClient("block", ["reported as drainer"]), "sat1", "0x344", {
      now: () => NOW,
      failClosed: true,
    });
    expect(out.verdict).toBe("block"); // never downgraded
  });

  it("warns when an EOA has an EIP-7702 delegation", async () => {
    const fetchFn = makeFetch([
      {
        match: isEtherscan,
        body: txlist([]),
        // no etherscan route needed — only the rpc matters here
        throw: new Error("no etherscan in this test"),
      },
      // 0xef0100 prefix = EIP-7702 delegation indicator + delegated address
      { match: isRpc, body: { jsonrpc: "2.0", id: 1, result: "0xef0100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } },
    ]);
    const out = await enrichCounterparty(stubClient("allow"), "sat1", "0x354", {
      etherscanApiKey: "K",
      evmRpcUrl: "http://rpc",
      fetchFn,
      now: () => NOW,
    });
    expect(out.verdict).toBe("warn");
    expect(out.reasons.join(" ")).toMatch(/EIP-7702/);
    expect(out.signals.find((s) => s.name === "contract")?.risk).toBe(true);
  });
});
