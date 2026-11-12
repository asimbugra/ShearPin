/**
 * WARN-APPROVE DEMO — the human-approval loop, closed end-to-end,
 * with STRICT role separation:
 *
 *   - the AGENT holds only a function-call key (request_signature, no
 *     deposits, no owner methods). it runs the counterparty check and
 *     submits the spend.
 *   - the OWNER (the approving human) signs set_allowed_recipients with
 *     their own key from their own client. the agent key physically
 *     cannot do this — and must never hold the owner key.
 *
 * flow (solution A: vet-by-approval):
 *   1. an unvetted recipient -> contract verdict WARN (unvetted)
 *   2. the wrapper asks the human (onWarn) — the human approves
 *   3. guardedSpend({ autoAllowApproved, ownerClient }) -> the OWNER's
 *      client adds the recipient to the allowlist
 *   4. the AGENT's function-call key submits the spend: allow + signature
 *
 * run: node agent-sim/warn-approve-demo.mjs
 */
import { readFileSync } from "node:fs";
import { ShearPinClient } from "@shearpin/sdk";
import { config } from "dotenv";
import { fileURLToPath } from "node:url";

config({ path: fileURLToPath(new URL("../.env", import.meta.url)), quiet: true });

const CONTRACT = process.env.SHEARPIN_CONTRACT;
const OWNER = process.env.SHEARPIN_SIGNER_ID;
const OWNER_KEY = process.env.SHEARPIN_OWNER_KEY;
const POLICY = process.env.SHEARPIN_POLICY || "sat1";
const SEPOLIA = 11155111n;

const keyJson = JSON.parse(readFileSync(fileURLToPath(new URL("../agent-key.json", import.meta.url)), "utf8"));

const log = (...a) => console.log(...a);

// a NEW recipient no one has vetted yet (not in the allowlist)
const NEW_VENDOR = "0x" + [...Array(40)].map(() => "0123456789abcdef"[Math.floor(Math.random() * 16)]).join("");

// two clients, two keys, two roles — this is the whole point of the demo
const agent = new ShearPinClient({
  network: "testnet",
  contractId: CONTRACT,
  signerAccountId: keyJson.account_id,
  signerSecretKey: keyJson.secret_key, // FUNCTION-CALL key: request_signature only
});
const owner = new ShearPinClient({
  network: "testnet",
  contractId: CONTRACT,
  signerAccountId: OWNER,
  signerSecretKey: OWNER_KEY, // full key: freeze / reset / allowlists
});
log("=== ShearPin warn-approve demo: human approval closes the loop (two-key role separation) ===");
log("");
log("[keys]  agent:", keyJson.account_id, "(function-call key)");
log("[keys]  owner:", OWNER, "(signs owner writes ONLY here)");
log("");
log("[agent] task: pay 0.001 ETH to a NEW vendor", NEW_VENDOR);

// ---------- step 1: the verdict (what the agent sees) ----------
const before = await agent.checkCounterparty(POLICY, NEW_VENDOR);
log("[wrapper] counterparty check ->", before.verdict.toUpperCase());
for (const r of before.reasons) log("           reason:", r);
if (before.verdict !== "warn") {
  log("[wrapper] expected warn for an unvetted recipient — aborting");
  process.exit(1);
}

// ---------- step 2+3: ask the human; the OWNER signs the vetting ----------
log("");
log("[human] approving the payment (owner decision)...");
const out = await agent.guardedSpend(
  {
    policyId: POLICY,
    derivationPath: "eth/0",
    keyType: "ecdsa",
    payload: ShearPinClient.buildEip155TransferRlp({
      to: NEW_VENDOR,
      value: 1_000_000_000_000_000n, // 0.001 ETH
      chainId: SEPOLIA,
    }),
  },
  NEW_VENDOR,
  async (reasons) => {
    log("[human] reasons shown:", reasons.join(" | "));
    return true; // explicit human approval
  },
  { autoAllowApproved: true, ownerClient: owner }, // OWNER signs set_allowed_recipients (agent key can't)
);

// ---------- step 4: the verdict after approval ----------
log("");
if (out.kind === "refused") {
  log("[wrapper] REFUSED:", out.verdict, out.reasons.join(" | "));
  process.exit(1);
}
log("[human] owner signs set_allowed_recipients (agent key can't)");
log("[agent] spend via function-call key ->", out.verdict.toUpperCase(), out.reason ? `(${out.reason})` : "");
log("[agent] near tx:", out.nearTxHash ?? "-");

const after = await agent.checkCounterparty(POLICY, NEW_VENDOR);
log("[wrapper] counterparty check now ->", after.verdict.toUpperCase(), "(the approved vendor is allowlisted)");

const policy = await agent.getPolicy(POLICY);
log("[chain]   allowlist now has", policy.allowed_recipients.length, "entries");
log("");
log("WARN-APPROVE END-TO-END:", out.verdict === "allow" && after.verdict === "allow" ? "PASS" : "FAIL");
