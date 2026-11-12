/**
 * WARN-APPROVE DEMO — the human-approval loop, closed end-to-end.
 *
 * prompt's requirement: on a warn verdict the wrapper asks a human. this
 * demo shows the FULL flow (solution A: vet-by-approval):
 *   1. an unvetted recipient -> contract verdict WARN (unvetted)
 *   2. the wrapper asks the human (onWarn) — here the human approves
 *   3. approval = vetting: the owner's key adds the recipient to the
 *      policy allowlist (set_allowed_recipients) via guardedSpend's
 *      autoAllowApproved
 *   4. the spend goes through: allow + MPC signature
 *
 * without step 3 the on-chain recipient gate would deny the spend the
 * human just approved (and snap the pin) — approval must mean something.
 *
 * run: node agent-sim/warn-approve-demo.mjs
 */
import { ShearPinClient } from "@shearpin/sdk";
import { config } from "dotenv";
import { fileURLToPath } from "node:url";

config({ path: fileURLToPath(new URL("../.env", import.meta.url)), quiet: true });

const CONTRACT = process.env.SHEARPIN_CONTRACT;
const OWNER = process.env.SHEARPIN_SIGNER_ID;
const OWNER_KEY = process.env.SHEARPIN_OWNER_KEY;
const POLICY = process.env.SHEARPIN_POLICY || "sat1";
const SEPOLIA = 11155111n;

const log = (...a) => console.log(...a);

// a NEW recipient no one has vetted yet (not in the allowlist)
const NEW_VENDOR = "0x" + [...Array(40)].map(() => "0123456789abcdef"[Math.floor(Math.random() * 16)]).join("");

const client = new ShearPinClient({
  network: "testnet",
  contractId: CONTRACT,
  // the OWNER signs here: approval is an owner action (set_allowed_recipients)
  signerAccountId: OWNER,
  signerSecretKey: OWNER_KEY,
});

log("=== ShearPin warn-approve demo: human approval closes the loop ===");
log("");
log("[agent] task: pay 0.001 ETH to a NEW vendor", NEW_VENDOR);

// ---------- step 1: the verdict (what the agent sees) ----------
const before = await client.checkCounterparty(POLICY, NEW_VENDOR);
log("[wrapper] counterparty check ->", before.verdict.toUpperCase());
for (const r of before.reasons) log("           reason:", r);
if (before.verdict !== "warn") {
  log("[wrapper] expected warn for an unvetted recipient — aborting");
  process.exit(1);
}

// ---------- step 2+3: ask the human; approval = vetting ----------
log("");
log("[human] approving the payment (owner decision)...");
const out = await client.guardedSpend(
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
  { autoAllowApproved: true }, // approval adds the recipient to the allowlist
);

// ---------- step 4: the verdict after approval ----------
log("");
if (out.kind === "refused") {
  log("[wrapper] REFUSED:", out.verdict, out.reasons.join(" | "));
  process.exit(1);
}
log("[wrapper] spend verdict ->", out.verdict.toUpperCase(), out.reason ? `(${out.reason})` : "");
log("[wrapper] near tx:", out.nearTxHash ?? "-");

const after = await client.checkCounterparty(POLICY, NEW_VENDOR);
log("[wrapper] counterparty check now ->", after.verdict.toUpperCase(), "(the approved vendor is allowlisted)");

const policy = await client.getPolicy(POLICY);
log("[chain]   allowlist now has", policy.allowed_recipients.length, "entries");
log("");
log("WARN-APPROVE END-TO-END:", out.verdict === "allow" && after.verdict === "allow" ? "PASS" : "FAIL");
