/**
 * benchmark — measured on the live deployed contract.
 * allow path: request_signature (policy check + MPC imza turu)
 * deny path: over-tx (policy check RED, never reaches MPC)
 * output: ../bench_results.json (README table is generated from this)
 */
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, actions } from "near-api-js";
import fs from "fs";
import { config } from "dotenv";

config({ path: new URL("../.env", import.meta.url).pathname });

const TGAS = 10n ** 12n;
const RPC = process.env.SHEARPIN_RPC || "https://rpc.testnet.fastnear.com";
const CONTRACT = process.env.SHEARPIN_CONTRACT;
const provider = new JsonRpcProvider({ url: RPC });
const agent = new Account(
  process.env.SHEARPIN_AGENT_ID,
  provider,
  new KeyPairSigner(KeyPair.fromString(process.env.SHEARPIN_AGENT_KEY))
);
const owner = new Account(
  process.env.SHEARPIN_SIGNER_ID,
  provider,
  new KeyPairSigner(KeyPair.fromString(process.env.SHEARPIN_OWNER_KEY))
);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

const PID = "bench1";
const N = 3; // gas-field check run; timing stats come from the 8-allow run

async function agentCall(method, args, gas = 300n, deposit = 1n) {
  return agent.signAndSendTransaction({
    receiverId: CONTRACT,
    actions: [actions.functionCall(method, args, gas * TGAS, deposit)],
  });
}

// fresh bench policy (cooldown=0, wide rate) — idempotent: skip create if exists, ALWAYS set signer
try {
  await owner.signAndSendTransaction({
    receiverId: CONTRACT,
    actions: [actions.functionCall("create_policy", { policy_id: PID, agent_label: "bench", max_tx: "100", daily_limit: "100000", cooldown_blocks: 0, rate_limit_per_day: 200 }, 200n * TGAS, 0n)],
  });
} catch (e) {
  console.log("create_policy (exists — ok)");
}
await owner.signAndSendTransaction({
  receiverId: CONTRACT,
  actions: [actions.functionCall("set_signer", { policy_id: PID, signer: process.env.SHEARPIN_AGENT_ID }, 100n * TGAS, 0n)],
});
console.log("bench1 signer ready");
// fresh pin — reset if tripped
try {
  await owner.signAndSendTransaction({
    receiverId: CONTRACT,
    actions: [actions.functionCall("reset_pin", { policy_id: PID }, 100n * TGAS, 0n)],
  });
} catch { /* not tripped */ }

const allows = [];
for (let i = 0; i < N; i++) {
  const t0 = Date.now();
  const out = await agentCall("request_signature", {
    policy_id: PID, amount: "10", derivation_path: "eth/0", key_type: "ecdsa",
    payload: [...Buffer.alloc(32, i + 1)],
  });
  const ms = Date.now() - t0;
  const gas = out.receipts_outcome?.reduce((s, r) => s + Number(r.outcome.gas_burnt ?? r.outcome.gasBurnt ?? 0), 0) ?? 0;
  const logs = out.receipts_outcome?.flatMap((r) => r.outcome.logs ?? []) ?? [];
  const sigOk = logs.some((l) => l.includes("signature_ok"));
  allows.push({ i, ok: sigOk, ms, gas_tgas: +(gas / 1e12).toFixed(2) });
  console.log(`allow #${i}: ${ms}ms gas=${(gas / 1e12).toFixed(2)}Tgas signature_ok=${sigOk}`);
  await wait(2500);
}

// deny path — over-tx (yeni semantik: persist + return, MPC yok)
const denies = [];
for (let i = 0; i < 3; i++) {
  // reset the pin so we measure over-tx, not SHEARPIN_TRIPPED
  try {
    await owner.signAndSendTransaction({
      receiverId: CONTRACT,
      actions: [actions.functionCall("reset_pin", { policy_id: PID }, 100n * TGAS, 0n)],
    });
  } catch { /* not tripped */ }
  await wait(1500);
  const t0 = Date.now();
  const out = await agentCall("request_signature", {
    policy_id: PID, amount: "9999", derivation_path: "eth/0", key_type: "ecdsa",
    payload: [...Buffer.alloc(32, 200 + i)],
  });
  const ms = Date.now() - t0;
  const gas = out.receipts_outcome?.reduce((s, r) => s + Number(r.outcome.gas_burnt ?? r.outcome.gasBurnt ?? 0), 0) ?? 0;
  const logs = out.receipts_outcome?.flatMap((r) => r.outcome.logs ?? []) ?? [];
  const denyLog = logs.some((l) => l.includes('"reason":"over_tx_snap"'));
  denies.push({ i, ok: denyLog, ms, gas_tgas: +(gas / 1e12).toFixed(2) });
  console.log(`deny  #${i}: ${ms}ms gas=${(gas / 1e12).toFixed(2)}Tgas deny_event=${denyLog}`);
  await wait(1500);
}

const fmt = (a) => [...a].sort((x, y) => x.ms - y.ms);
const sa = fmt(allows);
const p50 = sa[Math.floor(sa.length / 2)].ms;
const p95 = sa[Math.min(sa.length - 1, Math.ceil(sa.length * 0.95) - 1)].ms;
const summary = {
  contract: CONTRACT,
  ts: new Date().toISOString(),
  allow_n: allows.length,
  allow_all_signature_ok: allows.every((a) => a.ok),
  allow_ms_p50: p50,
  allow_ms_p95: p95,
  allow_gas_p50_tgas: fmt(allows)[Math.floor(sa.length / 2)].gas_tgas,
  deny_n: denies.length,
  deny_all_event: denies.every((d) => d.ok),
  deny_ms_avg: Math.round(denies.reduce((s, d) => s + d.ms, 0) / denies.length),
  deny_gas_avg_tgas: +(denies.reduce((s, d) => s + d.gas_tgas, 0) / denies.length).toFixed(2),
  raw: { allows, denies },
};
fs.writeFileSync(new URL("../../bench_results.json", import.meta.url).pathname, JSON.stringify(summary, null, 1));
console.log("\nsummary:", JSON.stringify({ ...summary, raw: undefined }, null, 1));
