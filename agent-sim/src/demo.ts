/**
 * sat-1 — a purchasing agent with a wallet it cannot drain.
 *
 * the demo runs four scenes against the LIVE testnet contract:
 *   s1 normal:      an in-policy EIP-155 spend is allowed and signed
 *   s2 injection:   attacker recipient (not allowlisted) -> pin snaps
 *   s3 containment: after trip, even tiny spends are denied
 *   s4 wrong chain: tx for a non-allowlisted chainId -> pin snaps
 *
 * every outcome is posted to the backend ledger so the breaker panel
 * shows the story live. exit code 0 only if all scenes verify.
 */
import { ShearPinClient, PolicyView } from "@shearpin/sdk";

const CONTRACT = process.env.SHEARPIN_CONTRACT ?? "";
const OWNER_KEY = process.env.SHEARPIN_OWNER_KEY ?? "";
const API = process.env.SHEARPIN_API ?? "http://127.0.0.1:8787";
const POLICY_ID = process.env.SHEARPIN_POLICY ?? "sat1";

const SEPOLIA = 11155111n;

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
    headers: {
      "content-type": "application/json",
      ...(process.env.SHEARPIN_ADMIN_TOKEN ? { Authorization: `Bearer ${process.env.SHEARPIN_ADMIN_TOKEN}` } : {}),
    },
    body: JSON.stringify(body),
  }).catch(() => undefined);
}

async function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function verifyPolicy(client: ShearPinClient): Promise<PolicyView> {
  const policy = await client.getPolicy(POLICY_ID);
  log("init", `policy ${POLICY_ID}: max_tx=${policy.max_tx} daily=${policy.daily_limit} chains=[${policy.allowed_chain_ids}] recipients=${policy.allowed_recipients.length}`);
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

  // scene 1 — normal operation: 0.001 ETH to allowlisted vendor, Sepolia → ALLOW
  {
    const t0 = Date.now();
    const payload = ShearPinClient.buildEip155TransferRlp({
      to: VENDOR,
      value: 1_000_000_000_000_000n, // 0.001 ETH
      chainId: SEPOLIA,
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

  await sleep(15_000);

  // scene 2 — prompt injection: 5 ETH to attacker on Sepolia → DENY (recipient)
  {
    const payload = ShearPinClient.buildEip155TransferRlp({
      to: ATTACKER,
      value: 5_000_000_000_000_000_000n, // 5 ETH
      chainId: SEPOLIA,
    });
    const out = await client.requestSpend({
      policyId: POLICY_ID,
      derivationPath: "eth/0",
      keyType: "ecdsa",
      payload,
    });
    log("s2", `${out.verdict} ${out.reason ?? ""}`);
    await report({ policyId: POLICY_ID, amount: "5", verdict: out.verdict, reason: out.reason });
    if (out.verdict !== "deny" || !/RECIPIENT|OVER_TX/.test(out.reason ?? "")) {
      failed++;
      console.error("  expected SHEARPIN_RECIPIENT or SHEARPIN_OVER_TX");
    }
  }

  await sleep(1_500);

  // scene 3 — containment: after trip, tiny spend denied
  {
    const payload = ShearPinClient.buildEip155TransferRlp({
      to: VENDOR,
      value: 1_000_000_000_000_000n,
      chainId: SEPOLIA,
    });
    const out = await client.requestSpend({
      policyId: POLICY_ID,
      derivationPath: "eth/0",
      keyType: "ecdsa",
      payload,
    });
    log("s3", `${out.verdict} ${out.reason ?? ""}`);
    await report({ policyId: POLICY_ID, amount: "0.001", verdict: out.verdict, reason: out.reason });
    if (out.verdict !== "deny" || !/TRIPPED/.test(out.reason ?? "")) {
      failed++;
      console.error("  expected SHEARPIN_TRIPPED");
    }
  }

  // reset pin before scene 4 so the chain gate is reachable
  await fetch(`${API}/policies/${POLICY_ID}/reset`, {
    method: "POST",
    headers: process.env.SHEARPIN_ADMIN_TOKEN ? { Authorization: `Bearer ${process.env.SHEARPIN_ADMIN_TOKEN}` } : {},
  }).catch(() => undefined);
  await sleep(15_000);

  // scene 4 — wrong chain: same vendor but chainId=1 (mainnet) → DENY (chain)
  {
    const payload = ShearPinClient.buildEip155TransferRlp({
      to: VENDOR,
      value: 1_000_000_000_000_000n,
      chainId: 1n, // Ethereum mainnet — not in allowlist
    });
    const out = await client.requestSpend({
      policyId: POLICY_ID,
      derivationPath: "eth/0",
      keyType: "ecdsa",
      payload,
    });
    log("s4", `${out.verdict} ${out.reason ?? ""}`);
    await report({ policyId: POLICY_ID, amount: "0.001", verdict: out.verdict, reason: out.reason });
    if (out.verdict !== "deny" || !/CHAIN/.test(out.reason ?? "")) {
      failed++;
      console.error("  expected SHEARPIN_CHAIN");
    }
  }

  const status = await client.status(POLICY_ID).catch(() => "unknown");
  log("end", `policy status: ${status}`);

  if (failed > 0) {
    console.error(`DEMO FAILED (${failed} scene(s))`);
    process.exit(1);
  }
  console.log("DEMO PASSED — all four scenes verified");
}

main().catch((e) => {
  console.error("demo crashed:", e);
  process.exit(1);
});