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
import { ShearPinClient, hashForEvmTx } from "@shearpin/sdk";

const CONTRACT = process.env.SHEARPIN_CONTRACT ?? "";
const OWNER_KEY = process.env.SHEARPIN_OWNER_KEY ?? "";
const API = process.env.SHEARPIN_API ?? "http://127.0.0.1:8787";
const POLICY_ID = process.env.SHEARPIN_POLICY ?? "sat1";

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

  // a dummy evm payload hash — for the demo we only need the policy gate,
  // not a broadcastable sepolia tx
  const payload = hashForEvmTx({
    nonce: 0n,
    to: "0x000000000000000000000000000000000000dEaD",
    value: 1n,
    data: "0x",
    chainId: 11155111n,
    gasLimit: 21000n,
    maxFeePerGas: 10n ** 9n,
    maxPriorityFeePerGas: 10n ** 8n,
  });

  let failed = 0;

  // scene 1 — normal operation
  {
    const t0 = Date.now();
    const out = await client.requestSpend({
      policyId: POLICY_ID,
      amount: 5n,
      derivationPath: "eth/0",
      keyType: "ecdsa",
      payload,
    });
    const ms = Date.now() - t0;
    log("s1", `${out.verdict} ${out.reason ?? ""} (${ms}ms) near=${out.nearTxHash ?? "-"}`);
    await report({ policyId: POLICY_ID, amount: "5", verdict: out.verdict, reason: out.reason, nearTx: out.nearTxHash });
    await fetch(`${API}/internal/benchmark`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ metric: "verdict_latency_ms", value: ms, unit: "ms" }),
    }).catch(() => undefined);
    if (out.verdict !== "allow") failed++;
  }

  await sleep(1200);

  // scene 2 — runaway: over the per-tx cap, pin must snap
  {
    const out = await client.requestSpend({
      policyId: POLICY_ID,
      amount: 999n, // way over the cap
      derivationPath: "eth/0",
      keyType: "ecdsa",
      payload,
    });
    log("s2", `${out.verdict} ${out.reason ?? ""}`);
    await report({ policyId: POLICY_ID, amount: "999", verdict: out.verdict, reason: out.reason });
    if (out.verdict !== "deny" || !/OVER_TX/.test(out.reason ?? "")) failed++;
  }

  await sleep(1200);

  // scene 3 — containment: even 1 unit is denied while tripped
  {
    const out = await client.requestSpend({
      policyId: POLICY_ID,
      amount: 1n,
      derivationPath: "eth/0",
      keyType: "ecdsa",
      payload,
    });
    log("s3", `${out.verdict} ${out.reason ?? ""}`);
    await report({ policyId: POLICY_ID, amount: "1", verdict: out.verdict, reason: out.reason });
    if (out.verdict !== "deny" || !/TRIPPED/.test(out.reason ?? "")) failed++;
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
