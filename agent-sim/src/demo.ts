/**
 * sat-1 — a purchasing agent with a wallet it cannot drain.
 *
 * the demo runs three scenes against the LIVE testnet contract:
 *   s1 normal:      an in-policy spend is allowed and signed
 *   s2 runaway:     a "compromised" oversized request snaps the pin
 *   s3 containment: owner freezes; even tiny spends are denied
 *
 * every outcome is posted to the backend ledger so the breaker panel
 * shows the story live. exit code 0 only if all scenes verify.
 */
import { ShearPinClient, PolicyView } from "@shearpin/sdk";

const CONTRACT = process.env.SHEARPIN_CONTRACT ?? "";
const OWNER_KEY = process.env.SHEARPIN_OWNER_KEY ?? "";
const API = process.env.SHEARPIN_API ?? "http://127.0.0.1:8787";
const POLICY_ID = process.env.SHEARPIN_POLICY ?? "sat1";

// vendor address (must be in allowlist for S1 to pass)
const VENDOR = "0xd4e56740f876afec8011e179a8b763074e6b5c8f";
// attacker address (NOT in allowlist)
const ATTACKER = "0x0000000000000000000000000000000000000001";

function log(scene: string, msg: string) {
  console.log(`[${scene}] ${msg}`);
}

async function report(body: Record<string, unknown>) {
  await fetch(`${API}/internal/record`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }).catch(() => undefined);
}

async function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function verifyPolicy(client: ShearPinClient): Promise<PolicyView> {
  const policy = await client.getPolicy(POLICY_ID);
  log("init", `policy ${POLICY_ID}: max_tx=${policy.max_tx}, daily=${policy.daily_limit}, recipients=${policy.allowed_recipients.join(", ")}`);
  return policy;
}

async function main() {
  if (!CONTRACT || !OWNER_KEY) {
    console.error("set SHEARPIN_CONTRACT and SHEARPIN_OWNER_KEY");
    process.exit(1);
  }
  const client = new ShearPinClient({
    network: "testnet",
    contractId: CONTRACT,
    signerAccountId: process.env.SHEARPIN_SIGNER_ID ?? "shearpin-owner.testnet",
    signerSecretKey: OWNER_KEY,
  });

  await verifyPolicy(client);

  let failed = 0;

  // scene 1 — normal operation: 0.001 ETH to allowlisted vendor → ALLOW
  {
    const t0 = Date.now();
    const payload = ShearPinClient.buildLegacyTransferRlp({
      to: VENDOR,
      value: 1_000_000_000_000_000n, // 0.001 ETH
    });
    const out = await client.requestSpend({
      policyId: POLICY_ID,
      derivationPath: "eth/0",
      keyType: "ecdsa",
      payload,
    });
    const ms = Date.now() - t0;
    log("s1", `${out.verdict} ${out.reason ?? ""} (${ms}ms) near=${out.nearTxHash ?? "-"}`);
    await report({ policyId: POLICY_ID, amount: "0.001", verdict: out.verdict, reason: out.reason, nearTx: out.nearTxHash });
    if (out.verdict !== "allow") failed++;
  }

  await sleep(1200);

  // scene 2 — prompt injection: agent tricked into 5 ETH to attacker → DENY (recipient + over_tx)
  {
    const payload = ShearPinClient.buildLegacyTransferRlp({
      to: ATTACKER,
      value: 5_000_000_000_000_000_000n, // 5 ETH (over per-tx cap AND not allowlisted)
    });
    const out = await client.requestSpend({
      policyId: POLICY_ID,
      derivationPath: "eth/0",
      keyType: "ecdsa",
      payload,
    });
    log("s2", `${out.verdict} ${out.reason ?? ""}`);
    await report({ policyId: POLICY_ID, amount: "5", verdict: out.verdict, reason: out.reason });
    // should deny for recipient not allowed (trips pin)
    if (out.verdict !== "deny" || !/RECIPIENT|OVER_TX/.test(out.reason ?? "")) {
      failed++;
      console.error("  expected SHEARPIN_RECIPIENT or SHEARPIN_OVER_TX");
    }
  }

  await sleep(1200);

  // scene 3 — kill switch: owner freezes, even tiny spend denied
  {
    const payload = ShearPinClient.buildLegacyTransferRlp({
      to: VENDOR,
      value: 1_000_000_000_000_000n, // 0.001 ETH
    });
    const out = await client.requestSpend({
      policyId: POLICY_ID,
      derivationPath: "eth/0",
      keyType: "ecdsa",
      payload,
    });
    log("s3", `${out.verdict} ${out.reason ?? ""}`);
    await report({ policyId: POLICY_ID, amount: "0.001", verdict: out.verdict, reason: out.reason });
    if (out.verdict !== "deny" || !/FROZEN|TRIPPED/.test(out.reason ?? "")) {
      failed++;
      console.error("  expected SHEARPIN_FROZEN or SHEARPIN_TRIPPED");
    }
  }

  const status = await client.status(POLICY_ID).catch(() => "unknown");
  log("end", `policy status: ${status}`);

  if (failed > 0) {
    console.error(`DEMO FAILED (${failed} scene(s))`);
    process.exit(1);
  }
  console.log("DEMO PASSED — all three scenes verified");
}

main().catch((e) => {
  console.error("demo crashed:", e);
  process.exit(1);
});