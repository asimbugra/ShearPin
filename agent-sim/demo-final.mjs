import { Account, JsonRpcProvider, KeyPairSigner, KeyPair, actions } from "near-api-js";
import { config } from "dotenv";
config({ path: "/opt/data/projects/ShearPin/.env" });

const TGAS = 10n ** 12n;
const RPC = process.env.SHEARPIN_RPC || "https://rpc.testnet.fastnear.com";
const CONTRACT = process.env.SHEARPIN_CONTRACT;
const AGENT_ID = process.env.SHEARPIN_AGENT_ID;
const AGENT_KEY = process.env.SHEARPIN_AGENT_KEY;
const POLICY_ID = "demo2";

const agentKp = KeyPair.fromString(AGENT_KEY);
const agentSigner = new KeyPairSigner(agentKp);
const provider = new JsonRpcProvider({ url: RPC });
const agentAcct = new Account(AGENT_ID, provider, agentSigner);

async function call(method, args, gas = 300n) {
  return await agentAcct.signAndSendTransaction({
    receiverId: CONTRACT,
    actions: [actions.functionCall(method, args, gas * TGAS, 1n)], // 1 NEAR deposit
  });
}

async function callOwner(method, args, gas = 200n) {
  const { KeyPair, KeyPairSigner } = await import("near-api-js");
  const ownerKp = KeyPair.fromString(process.env.SHEARPIN_OWNER_KEY);
  const ownerSigner = new KeyPairSigner(ownerKp);
  const ownerAcct = new Account(process.env.SHEARPIN_SIGNER_ID, provider, ownerSigner);
  return await ownerAcct.signAndSendTransaction({
    receiverId: CONTRACT,
    actions: [actions.functionCall(method, args, gas * TGAS, 0n)],
  });
}

const wait = (ms) => new Promise(r => setTimeout(r, ms));

async function extractLogs(result) {
  const logs = [];
  if (result.receipts_outcome) {
    for (const r of result.receipts_outcome) {
      if (r.outcome?.logs) logs.push(...r.outcome.logs);
    }
  }
  if (result.transaction_outcome?.outcome?.logs) {
    logs.push(...result.transaction_outcome.outcome.logs);
  }
  return logs;
}

async function main() {
  console.log("=== ShearPin Live Demo on", CONTRACT, "===");
  console.log("Policy:", POLICY_ID);
  console.log("Agent:", AGENT_ID);
  console.log("");

  // SCENE 1 — allow + MPC signature request
  console.log("--- SCENE 1: ALLOW (in-policy spend) ---");
  try {
    const payload = new Uint8Array(32).fill(1);
    const s1 = await call("request_signature", {
      policy_id: POLICY_ID,
      amount: "100", // well under max_tx=1000
      derivation_path: "eth/0",
      key_type: "ecdsa",
      payload: Array.from(payload),
    });
    const logs = await extractLogs(s1);
    const events = logs.filter(l => l.includes("event")).join(" | ");
    console.log("Status:", s1.finalExecutionStatus);
    console.log("Events:", events);
    console.log("Tx Hash:", s1.transaction.hash);
  } catch (e) {
    console.log("ERROR:", String(e.message ?? e).slice(0, 200));
  }

  await wait(8000); // wait for MPC callback

  // SCENE 2 — over-tx deny (amount > max_tx)
  console.log("\n--- SCENE 2: OVER_TX DENY (amount > max_tx) ---");
  try {
    const payload = new Uint8Array(32).fill(2);
    const s2 = await call("request_signature", {
      policy_id: POLICY_ID,
      amount: "2000", // exceeds max_tx=1000
      derivation_path: "eth/0",
      key_type: "ecdsa",
      payload: Array.from(payload),
    });
    console.log("UNEXPECTED ALLOW:", s2.finalExecutionStatus);
  } catch (e) {
    const msg = String(e.message ?? e);
    const reason = msg.match(/SHEARPIN_\w+/)?.[0] ?? msg.slice(0, 100);
    console.log("DENY REASON:", reason);
  }

  await wait(5000);

  // SCENE 3 — frozen deny (owner freezes, then request)
  console.log("\n--- SCENE 3: FROZEN DENY (owner freeze) ---");
  try {
    await callOwner("freeze", { policy_id: POLICY_ID }, 200n);
    console.log("Freeze tx sent");
    await wait(3000);
  } catch (e) {
    console.log("Freeze error:", String(e).slice(0, 100));
  }

  try {
    const payload = new Uint8Array(32).fill(3);
    const s3 = await call("request_signature", {
      policy_id: POLICY_ID,
      amount: "100",
      derivation_path: "eth/0",
      key_type: "ecdsa",
      payload: Array.from(payload),
    });
    console.log("UNEXPECTED ALLOW:", s3.finalExecutionStatus);
  } catch (e) {
    const msg = String(e.message ?? e);
    const reason = msg.match(/SHEARPIN_\w+/)?.[0] ?? msg.slice(0, 100);
    console.log("DENY REASON:", reason);
  }

  console.log("\n=== DEMO COMPLETE ===");
}

main().catch(console.error);