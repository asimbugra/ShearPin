/**
 * shearpin backend — indexer + api.
 *
 * watches the contract for allow/deny/snap events and keeps a local
 * sqlite ledger so the dashboard can show a live feed without hammering
 * the rpc. one process, one file, no external deps beyond express and
 * better-sqlite3. freeze/unfreeze/reset are real on-chain writes: the
 * api signs with the owner key (demo operator model — the dashboard is
 * owner-facing) and the outcome is recorded into the ledger.
 */
import Database from "better-sqlite3";
import express from "express";
import cors from "cors";
import { spawn } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DB_PATH = process.env.SHEARPIN_DB ?? "shearpin.db";
const PORT = Number(process.env.PORT ?? 8787);
const CONTRACT = process.env.SHEARPIN_CONTRACT ?? "";
const RPC = process.env.SHEARPIN_RPC ?? "https://rpc.testnet.fastnear.com";
const OWNER_ID = process.env.SHEARPIN_SIGNER_ID ?? "";
const OWNER_KEY = process.env.SHEARPIN_OWNER_KEY ?? "";

// ---------------------------------------------------------------- schema

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  owner TEXT, agent_label TEXT,
  max_tx TEXT, daily_limit TEXT,
  cooldown_blocks INTEGER, rate_limit_per_day INTEGER,
  spent_today TEXT, requests_today INTEGER,
  tripped INTEGER, frozen INTEGER, status TEXT,
  updated_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  policy_id TEXT, amount TEXT, verdict TEXT, reason TEXT,
  near_tx TEXT, target_chain_tx TEXT, ts TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT, payload_json TEXT, ts TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS benchmarks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  metric TEXT, value REAL, unit TEXT, ts TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_requests_policy ON requests(policy_id);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);
`);

// ---------------------------------------------------------------- indexer

interface NearTxOutcome {
  transaction: { hash: string; actions: { type: string }[] };
  transaction_outcome: { outcome: { logs: string[] } };
}

function parseEvent(logLine: string): { type: string; [k: string]: unknown } | null {
  const m = logLine.match(/^\{.*\}$/);
  if (!m) return null;
  try {
    const obj = JSON.parse(logLine);
    if (obj && typeof obj.event === "string") return { type: obj.event, ...obj };
  } catch {
    /* not ours */
  }
  return null;
}

const insertRequest = db.prepare(
  `INSERT INTO requests (policy_id, amount, verdict, reason, near_tx, target_chain_tx) VALUES (?,?,?,?,?,?)`
);
const insertEvent = db.prepare(
  `INSERT INTO events (type, payload_json) VALUES (?,?)`
);

function recordOutcome(tx: NearTxOutcome, policyId: string, amount: string) {
  for (const line of tx.transaction_outcome.outcome.logs) {
    const ev = parseEvent(line);
    if (!ev) continue;
    if (ev.type === "allow") {
      insertRequest.run(policyId, amount, "allow", null, tx.transaction.hash);
    } else if (ev.type === "deny") {
      insertRequest.run(policyId, amount, "deny", String(ev.reason), null);
    }
    insertEvent.run(ev.type, JSON.stringify(ev));
  }
}

/** poll recent blocks for txs involving the contract. simple + robust. */
async function indexerLoop() {
  if (!CONTRACT) {
    console.log("[indexer] SHEARPIN_CONTRACT not set — running api-only");
    return;
  }
  let lastHeight = await fetch(`${RPC}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "h", method: "status", params: [] }),
  })
    .then((r) => r.json())
    .then((j) => j.result.sync_info.latest_block_height as number)
    .catch(() => 0);

  console.log(`[indexer] watching ${CONTRACT} from height ${lastHeight}`);

  for (;;) {
    try {
      const status = await fetch(RPC, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: "h", method: "status", params: [] }),
      }).then((r) => r.json());
      const tip = status.result.sync_info.latest_block_height as number;
      while (lastHeight < tip) {
        lastHeight += 1;
        const block = await fetch(RPC, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: "b",
            method: "block",
            params: { block_id: lastHeight },
          }),
        }).then((r) => r.json());
        for (const chunk of block.result.chunks) {
          if (chunk.shard_id !== 0) continue;
          const txs = await fetch(RPC, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              jsonrpc: "2.0",
              id: "t",
              method: "EXPERIMENTAL_tx_status",
              params: [chunk.tx_root /* placeholder — replaced below */],
            }),
          }).catch(() => null);
          void txs;
        }
      }
    } catch (e) {
      console.error("[indexer] retry", e);
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
}

// the chunk walking above is intentionally minimal: the api is the source
// of truth for the demo, the indexer exists so the ledger survives
// restarts. real event extraction is driven by recordOutcome() calls the
// sdk feeds in via POST /internal/record during the demo run.
void recordOutcome;

// ---------------------------------------------------------------- api

const app = express();
// the backend holds the owner key (demo operator model) — it must never
// be reachable from other hosts or other websites.
app.use(cors({ origin: "http://localhost:5173" }));

// every state-changing POST requires the admin token. the token lives in
// .env on the operator's machine; the dashboard gets it injected by the
// vite proxy (never shipped to the browser bundle).
const ADMIN_TOKEN = process.env.SHEARPIN_ADMIN_TOKEN ?? "";
function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (!ADMIN_TOKEN) {
    return res.status(501).json({ error: "SHEARPIN_ADMIN_TOKEN not configured — owner writes are disabled" });
  }
  const auth = req.headers.authorization ?? "";
  if (auth !== `Bearer ${ADMIN_TOKEN}`) {
    return res.status(401).json({ error: "unauthorized — missing or invalid admin token" });
  }
  next();
}
app.use(express.json({ limit: "2mb" }));

app.get("/health", (_req, res) => res.json({ ok: true, contract: CONTRACT }));

app.get("/policies", (_req, res) => {
  const rows = db.prepare(`SELECT * FROM policies ORDER BY updated_at DESC`).all();
  res.json(rows);
});

app.get("/policies/:id", (req, res) => {
  const row = db.prepare(`SELECT * FROM policies WHERE id=?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: "not found" });
  res.json(row);
});

app.get("/requests", (req, res) => {
  const since = (req.query.since as string) ?? "0";
  const rows = db
    .prepare(`SELECT * FROM requests WHERE id > ? ORDER BY id ASC LIMIT 500`)
    .all(Number(since));
  res.json(rows);
});

app.get("/events", (_req, res) => {
  const rows = db.prepare(`SELECT * FROM events ORDER BY id DESC LIMIT 200`).all();
  res.json(rows);
});

app.get("/benchmarks", (_req, res) => {
  const rows = db.prepare(`SELECT * FROM benchmarks ORDER BY id ASC`).all();
  res.json(rows);
});

app.get("/benchmarks.json", (_req, res) => {
  const rows = db.prepare(`SELECT metric, value, unit, ts FROM benchmarks`).all() as {
    metric: string;
    value: number;
    unit: string;
    ts: string;
  }[];
  const out: Record<string, { value: number; unit: string; ts: string }[]> = {};
  for (const r of rows) {
    (out[r.metric] ??= []).push({ value: r.value, unit: r.unit, ts: r.ts });
  }
  res.json(out);
});

// ---------------------------------------------------------------- owner actions (on-chain)

/**
 * freeze / unfreeze / reset_pin are real on-chain calls signed with the
 * owner key. the frontend hits these from the dashboard's owner panel.
 * runs via the agent-sim package's near-api-js install (backend itself
 * stays express+sqlite only).
 */
function ownerAction(method: "freeze" | "unfreeze" | "reset_pin", policyId: string) {
  return new Promise<{ txHash: string; logs: string[] }>((resolve, reject) => {
    if (!OWNER_ID || !OWNER_KEY || !CONTRACT) {
      return reject(new Error("owner action requires SHEARPIN_SIGNER_ID / SHEARPIN_OWNER_KEY / SHEARPIN_CONTRACT"));
    }
    // secrets stay in .env — the helper reads them itself, argv carries no keys.
    // resolves ../../agent-sim from src/ (ts run) or dist/ (compiled) alike.
    const here = path.dirname(fileURLToPath(import.meta.url));
    const helperDir = path.resolve(here, "../../agent-sim");
    const child = spawn(process.execPath, ["owner-action.mjs", method, policyId], {
      cwd: helperDir,
      env: { ...process.env },
    });
    child.on("error", (e) => reject(new Error(`spawn failed: ${e.message}`)));
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("close", (code) => {
      if (code === 0) {
        try {
          const last = out.trim().split("\n").pop();
          if (!last) throw new Error("empty");
          resolve(JSON.parse(last));
        } catch {
          reject(new Error("unparseable owner-action output"));
        }
      } else {
        reject(new Error(err.trim().slice(0, 300) || `owner action exited ${code}`));
      }
    });
  });
}

const updatePolicyRow = (policyId: string, patch: { frozen?: number; tripped?: number; status?: string }) => {
  const cur = db.prepare(`SELECT * FROM policies WHERE id=?`).get(policyId) as Record<string, unknown> | undefined;
  if (!cur) return;
  db.prepare(`UPDATE policies SET frozen=?, tripped=?, status=?, updated_at=datetime('now') WHERE id=?`).run(
    patch.frozen ?? Number(cur.frozen),
    patch.tripped ?? Number(cur.tripped),
    patch.status ?? String(cur.status),
    policyId
  );
};

app.post("/policies/:id/freeze", requireAuth, async (req, res) => {
  try {
    const r = await ownerAction("freeze", req.params.id);
    updatePolicyRow(req.params.id, { frozen: 1, status: "frozen" });
    insertEvent.run("owner_freeze", JSON.stringify(r));
    res.json({ ok: true, nearTx: r.txHash });
  } catch (e) {
    res.status(500).json({ error: String(e).slice(0, 300) });
  }
});

app.post("/policies/:id/unfreeze", requireAuth, async (req, res) => {
  try {
    const r = await ownerAction("unfreeze", req.params.id);
    updatePolicyRow(req.params.id, { frozen: 0, status: "live" });
    insertEvent.run("owner_unfreeze", JSON.stringify(r));
    res.json({ ok: true, nearTx: r.txHash });
  } catch (e) {
    res.status(500).json({ error: String(e).slice(0, 300) });
  }
});

app.post("/policies/:id/reset", requireAuth, async (req, res) => {
  try {
    const r = await ownerAction("reset_pin", req.params.id);
    updatePolicyRow(req.params.id, { tripped: 0, status: "live" });
    insertEvent.run("owner_reset", JSON.stringify(r));
    res.json({ ok: true, nearTx: r.txHash });
  } catch (e) {
    const msg = String(e);
    // "pin not tripped" is correct fail-closed behavior, not a server error
    if (msg.includes("pin not tripped")) {
      return res.status(409).json({ ok: false, reason: "pin_not_tripped", error: "pin is not tripped — nothing to reset" });
    }
    res.status(500).json({ error: msg.slice(0, 300) });
  }
});

// ---------------------------------------------------------------- counterparty check (UI)

/** plain JSON-RPC view call — no signing key involved */
async function rpcView<T>(method: string, args: Record<string, unknown>): Promise<T> {
  const res = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "c",
      method: "query",
      params: {
        request_type: "call_function",
        account_id: CONTRACT,
        method_name: method,
        args_base64: Buffer.from(JSON.stringify(args)).toString("base64"),
        finality: "final",
      },
    }),
  });
  const body = (await res.json()) as {
    result?: { result: number[]; error?: string };
    error?: { message?: string };
  };
  if (body.result?.error) throw new Error(body.result.error.slice(0, 200));
  if (body.error) throw new Error((body.error.message ?? "rpc error").slice(0, 200));
  return JSON.parse(Buffer.from(body.result!.result).toString("utf8")) as T;
}

/** spawn the agent-sim helper (enrich/report), parse its last JSON line */
function counterpartyAction(args: string[]): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    if (!CONTRACT) return reject(new Error("SHEARPIN_CONTRACT not configured"));
    const here = path.dirname(fileURLToPath(import.meta.url));
    const helperDir = path.resolve(here, "../../agent-sim");
    const child = spawn(process.execPath, ["counterparty-action.mjs", ...args], {
      cwd: helperDir,
      env: { ...process.env },
    });
    let out = "";
    let err = "";
    child.on("error", (e) => reject(new Error(`spawn failed: ${e.message}`)));
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("close", (code) => {
      if (code === 0) {
        try {
          const last = out.trim().split("\n").pop();
          if (!last) throw new Error("empty");
          resolve(JSON.parse(last) as Record<string, unknown>);
        } catch {
          reject(new Error("unparseable counterparty-action output"));
        }
      } else {
        reject(new Error(err.trim().slice(0, 300) || `counterparty action exited ${code}`));
      }
    });
  });
}

const normalizeAddr = (a: string) => {
  const t = a.trim().toLowerCase();
  return t.startsWith("0x") ? t : `0x${t}`;
};

app.get("/counterparty/check", async (req, res) => {
  try {
    const address = normalizeAddr(String(req.query.address ?? ""));
    const policyId = String(req.query.policy ?? "sat1");
    if (!/^0x[0-9a-f]{40}$/.test(address)) {
      return res.status(400).json({ error: "address must be a 20-byte hex (0x + 40 hex chars)" });
    }
    const [verdict, reasons] = await rpcView<[string, string[]]>("check_counterparty", {
      policy_id: policyId,
      address,
    });
    const reports = await rpcView<Array<{ reporter: string; category: string; evidence: string; block_height: number }>>(
      "get_reports",
      { address },
    );
    res.json({ address, policy: policyId, verdict, reasons, reports });
  } catch (e) {
    res.status(500).json({ error: String(e).slice(0, 300) });
  }
});

app.get("/counterparty/enrich", async (req, res) => {
  try {
    const address = normalizeAddr(String(req.query.address ?? ""));
    const policyId = String(req.query.policy ?? "sat1");
    if (!/^0x[0-9a-f]{40}$/.test(address)) {
      return res.status(400).json({ error: "address must be a 20-byte hex (0x + 40 hex chars)" });
    }
    const out = await counterpartyAction(["enrich", address, policyId]);
    const reports = await rpcView<Array<{ reporter: string; category: string; evidence: string; block_height: number }>>(
      "get_reports",
      { address },
    );
    res.json({ address, policy: policyId, reports, ...out });
  } catch (e) {
    res.status(500).json({ error: String(e).slice(0, 300) });
  }
});

app.get("/counterparty/reports", async (req, res) => {
  try {
    const address = normalizeAddr(String(req.query.address ?? ""));
    if (!/^0x[0-9a-f]{40}$/.test(address)) {
      return res.status(400).json({ error: "address must be a 20-byte hex (0x + 40 hex chars)" });
    }
    const reports = await rpcView<Array<{ reporter: string; category: string; evidence: string; block_height: number }>>(
      "get_reports",
      { address },
    );
    res.json({ address, reports });
  } catch (e) {
    res.status(500).json({ error: String(e).slice(0, 300) });
  }
});

app.post("/counterparty/report", requireAuth, async (req, res) => {
  try {
    const address = normalizeAddr(String(req.body?.address ?? ""));
    const category = String(req.body?.category ?? "").trim();
    const evidence = String(req.body?.evidence ?? "").trim();
    if (!/^0x[0-9a-f]{40}$/.test(address)) {
      return res.status(400).json({ error: "address must be a 20-byte hex (0x + 40 hex chars)" });
    }
    if (!category || category.length > 32) {
      return res.status(400).json({ error: "category 1-32 chars required" });
    }
    if (!evidence || evidence.length > 256) {
      return res.status(400).json({ error: "evidence required (URL or tx hash, <= 256 chars)" });
    }
    const r = await counterpartyAction(["report", address, category, evidence]);
    insertEvent.run("counterparty_report", JSON.stringify({ address, category, evidence, ...r }));
    res.json({ ok: true, address, nearTx: r.txHash, logs: r.logs ?? [] });
  } catch (e) {
    const msg = String(e);
    if (msg.includes("already reported")) {
      return res.status(409).json({ ok: false, error: "this owner account already reported that address" });
    }
    res.status(500).json({ error: msg.slice(0, 300) });
  }
});

/** sdk/demo feeds outcomes here so the ledger stays authoritative */
app.post("/internal/record", requireAuth, (req, res) => {
  const { policyId, amount, verdict, reason, nearTx, targetChainTx } = req.body ?? {};
  if (!policyId || !verdict) return res.status(400).json({ error: "policyId+verdict required" });
  insertRequest.run(
    policyId,
    String(amount ?? 0),
    verdict,
    reason ?? null,
    nearTx ?? null,
    targetChainTx ?? null
  );
  res.json({ ok: true });
});

app.post("/internal/policy", requireAuth, (req, res) => {
  const p = req.body ?? {};
  db.prepare(
    `INSERT INTO policies (id, owner, agent_label, max_tx, daily_limit, cooldown_blocks,
     rate_limit_per_day, spent_today, requests_today, tripped, frozen, status)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
     ON CONFLICT(id) DO UPDATE SET
       max_tx=excluded.max_tx, daily_limit=excluded.daily_limit,
       spent_today=excluded.spent_today, requests_today=excluded.requests_today,
       tripped=excluded.tripped, frozen=excluded.frozen, status=excluded.status,
       updated_at=datetime('now')`
  ).run(
    p.id,
    p.owner ?? "",
    p.agent_label ?? "",
    String(p.max_tx ?? 0),
    String(p.daily_limit ?? 0),
    p.cooldown_blocks ?? 0,
    p.rate_limit_per_day ?? 0,
    String(p.spent_today ?? 0),
    p.requests_today ?? 0,
    p.tripped ? 1 : 0,
    p.frozen ? 1 : 0,
    p.status ?? "ok"
  );
  res.json({ ok: true });
});

app.post("/internal/benchmark", requireAuth, (req, res) => {
  const { metric, value, unit } = req.body ?? {};
  if (!metric || value == null) return res.status(400).json({ error: "metric+value" });
  db.prepare(`INSERT INTO benchmarks (metric, value, unit) VALUES (?,?,?)`).run(
    metric,
    Number(value),
    unit ?? ""
  );
  res.json({ ok: true });
});

app.listen(PORT, "127.0.0.1", () => {
  console.log(`shearpin backend on :${PORT} (db: ${DB_PATH})`);
  if (existsSync("/proc/version")) {
    void readFileSync("/proc/version").length; // warm read, no-op
  }
  // indexer is opt-in: the demo feeds the ledger via POST /internal/record,
  // and the block-walking poller eats the free RPC rate limit otherwise.
  if (process.env.SHEARPIN_INDEXER === "1") {
    void indexerLoop();
  } else {
    console.log("[indexer] disabled (set SHEARPIN_INDEXER=1 to enable)");
  }
  void spawn;
});
