/**
 * shearpin live demo — 3 scenes, real on-chain calls, recorded to the ledger.
 * S1 allow: in-policy spend → mpc sign (signature_ok)
 * S2 over_tx: over-limit request → SHEARPIN_OVER_TX, pin snaps
 * S3 reset: owner reset_pin → agent tekrar harcar
 * usage: node demo-live2.mjs [policy_id]   (default: demo2)
 */
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, actions } from "near-api-js";
import { config } from "dotenv";

const POLICY_ID = process.argv[2] ?? "demo2";
config({ path: new URL("../.env", import.meta.url).pathname });

const TGAS = 10n ** 12n;
const RPC = process.env.SHEARPIN_RPC || "https://rpc.testnet.fastnear.com";
const CONTRACT = process.env.SHEARPIN_CONTRACT;
const API = process.env.SHEARPIN_API || "http://127.0.0.1:8787";
const AGENT_ID = process.env.SHEARPIN_AGENT_ID;
const AGENT_KEY = process.env.SHEARPIN_AGENT_KEY;

const provider = new JsonRpcProvider({ url: RPC });
const agentAcct = new Account(AGENT_ID, provider, new KeyPairSigner(KeyPair.fromString(AGENT_KEY)));

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const FAIL = [];

async function feed(policyId, amount, verdict, reason, nearTx) {
  try {
    await fetch(`${API}/internal/record`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ policyId, amount, verdict, reason, nearTx, targetChainTx: null }),
    });
  } catch {
    /* ledger optional — demo must survive backend downtime */
  }
}

async function feedPolicy(p) {
  try {
    await fetch(`${API}/internal/policy`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(p),
    });
  } catch { /* ignore */ }
}

async function readPolicy(pid) {
  const raw = await provider.query({
    request_type: "call_function",
    finality: "final",
    account_id: CONTRACT,
    method_name: "get_policy",
    args_base64: Buffer.from(JSON.stringify({ policy_id: pid })).toString("base64"),
  });
  return JSON.parse(Buffer.from(raw.result).toString());
}


async function readPolicyOptimistic(pid) {
  const raw = await provider.query({
    request_type: "call_function",
    finality: "optimistic",
    account_id: CONTRACT,
    method_name: "get_policy",
    args_base64: Buffer.from(JSON.stringify({ policy_id: pid })).toString("base64"),
  });
  return JSON.parse(Buffer.from(raw.result).toString());
}

async function agentCall(method, args, gas = 300n, deposit = 1n) {
  return await agentAcct.signAndSendTransaction({
    receiverId: CONTRACT,
    actions: [actions.functionCall(method, args, gas * TGAS, deposit)],
  });
}

function logsOf(result) {
  const logs = [];
  for (const r of result.receipts_outcome ?? []) logs.push(...(r.outcome?.logs ?? []));
  if (result.transaction_outcome?.outcome?.logs) logs.push(...result.transaction_outcome.outcome.logs);
  return logs;
}

async function ownerCall(method, args, gas = 200n) {
  const ownerAcct = new Account(
    process.env.SHEARPIN_SIGNER_ID,
    provider,
    new KeyPairSigner(KeyPair.fromString(process.env.SHEARPIN_OWNER_KEY))
  );
  return await ownerAcct.signAndSendTransaction({
    receiverId: CONTRACT,
    actions: [actions.functionCall(method, args, gas * TGAS, 0n)],
  });
}

const assert = (cond, label) => {
  console.log(cond ? `  ✓ ${label}` : `  ✗ ${label}`);
  if (!cond) FAIL.push(label);
};

async function main() {
  console.log(`=== ShearPin Live Demo — ${CONTRACT} / policy ${POLICY_ID} ===\n`);

  // before the scenes: fresh pin, unfrozen
  console.log("[prep] unfreeze + read pin state");
  try { await ownerCall("unfreeze", { policy_id: POLICY_ID }); } catch { /* zaten unfrozen olabilir */ }
  const p0 = await readPolicy(POLICY_ID);
  const maxTx = Number(p0.max_tx);
  console.log(`  policy: max_tx=${maxTx} daily=${p0.daily_limit} spent=${p0.spent_today} rate=${p0.requests_today}/${p0.rate_limit_per_day}`);
  await feedPolicy({ id: POLICY_ID, owner: p0.owner, agent_label: p0.agent_label, max_tx: p0.max_tx, daily_limit: p0.daily_limit, cooldown_blocks: p0.cooldown_blocks, rate_limit_per_day: p0.rate_limit_per_day, spent_today: p0.spent_today, requests_today: p0.requests_today, tripped: p0.tripped, frozen: p0.frozen, status: p0.status });

  // reset the pin if tripped so S2 can trigger
  if (p0.tripped) {
    console.log("[prep] pin tripped — resetting");
    await ownerCall("reset_pin", { policy_id: POLICY_ID });
  }

  // ---------- S1: ALLOW ----------
  console.log("\n--- SCENE 1: ALLOW (in-policy spend) ---");
  const amt1 = Math.max(1, Math.floor(maxTx / 10));
  const s1 = await agentCall("request_signature", {
    policy_id: POLICY_ID,
    amount: String(amt1),
    derivation_path: "eth/0",
    key_type: "ecdsa",
    payload: Array.from(new Uint8Array(32).fill(1)),
  });
  const s1logs = logsOf(s1);
  console.log("  tx:", s1.transaction.hash);
  console.log("  events:", s1logs.join(" | "));
  assert(s1logs.some((l) => l.includes('"event":"allow"')), "S1 allow event on-chain");
  await wait(9000); // mpc callback
  const p1 = await readPolicy(POLICY_ID);
  assert(Number(p1.spent_today) > Number(p0.spent_today), "S1 spent_today increased");
  await feed(POLICY_ID, String(amt1), "allow", null, s1.transaction.hash);
  await feedPolicy({ id: POLICY_ID, owner: p1.owner, agent_label: p1.agent_label, max_tx: p1.max_tx, daily_limit: p1.daily_limit, cooldown_blocks: p1.cooldown_blocks, rate_limit_per_day: p1.rate_limit_per_day, spent_today: p1.spent_today, requests_today: p1.requests_today, tripped: p1.tripped, frozen: p1.frozen, status: p1.status });

  // ---------- S2: OVER_TX → pin kopar ----------
  console.log("\n--- SCENE 2: OVER_TX (amount > max_tx → pin SNAPS) ---");
  const amt2 = maxTx * 10;
  let s2deny = "";
  {
    // new semantics: deny = trip + persist + successful return (reason in value)
    const s2 = await agentCall("request_signature", {
      policy_id: POLICY_ID,
      amount: String(amt2),
      derivation_path: "eth/0",
      key_type: "ecdsa",
      payload: Array.from(new Uint8Array(32).fill(2)),
    });
    const logs2 = logsOf(s2);
    const denyLog = logs2.find((l) => l.includes('"reason":"over_tx_snap"'));
    s2deny = "SHEARPIN_OVER_TX";
    console.log("  deny event:", denyLog ?? "(log yok?)");
    console.log("  tx:", s2.transaction.hash, "(no request went to MPC — no sign log)");
    assert(!!denyLog, "S2 deny event on-chain");
    assert(!logs2.some((l) => l.includes("sign: predecessor")), "S2 made no MPC call");
  }
  const p2 = await readPolicyOptimistic(POLICY_ID);
  if (!p2.tripped) {
    await wait(4000); // finality gecikmesi — tekrar dene
  }
  const p2b = p2.tripped ? p2 : await readPolicyOptimistic(POLICY_ID);
  assert(p2b.tripped === true, "S2 pin tripped=true (chain)");
  await feed(POLICY_ID, String(amt2), "deny", s2deny || "SHEARPIN_OVER_TX", null);
  await feedPolicy({ id: POLICY_ID, owner: p2.owner, agent_label: p2.agent_label, max_tx: p2.max_tx, daily_limit: p2.daily_limit, cooldown_blocks: p2.cooldown_blocks, rate_limit_per_day: p2.rate_limit_per_day, spent_today: p2.spent_today, requests_today: p2.requests_today, tripped: p2.tripped, frozen: p2.frozen, status: p2.status });

  // ---------- S3: RESET → tekrar harcama ----------
  console.log("\n--- SCENE 3: RESET (owner reset_pin → agent spends again) ---");
  const r3 = await ownerCall("reset_pin", { policy_id: POLICY_ID });
  console.log("  reset tx:", r3.transaction.hash);
  const amt3 = Math.max(1, Math.floor(maxTx / 10));
  const s3 = await agentCall("request_signature", {
    policy_id: POLICY_ID,
    amount: String(amt3),
    derivation_path: "eth/0",
    key_type: "ecdsa",
    payload: Array.from(new Uint8Array(32).fill(3)),
  });
  const s3logs = logsOf(s3);
  console.log("  tx:", s3.transaction.hash);
  assert(s3logs.some((l) => l.includes('"event":"allow"')), "S3 allow after reset");
  await feed(POLICY_ID, String(amt3), "allow", null, s3.transaction.hash);
  const p3 = await readPolicy(POLICY_ID);
  await feedPolicy({ id: POLICY_ID, owner: p3.owner, agent_label: p3.agent_label, max_tx: p3.max_tx, daily_limit: p3.daily_limit, cooldown_blocks: p3.cooldown_blocks, rate_limit_per_day: p3.rate_limit_per_day, spent_today: p3.spent_today, requests_today: p3.requests_today, tripped: p3.tripped, frozen: p3.frozen, status: p3.status });

  console.log(`\n=== DEMO ${FAIL.length === 0 ? "PASS" : "FAIL"} — ${FAIL.length} failed ===`);
  if (FAIL.length) {
    console.log(FAIL.join("\n"));
    process.exit(1);
  }
}

main().catch((e) => {
  console.error("DEMO ERROR:", e);
  process.exit(1);
});
