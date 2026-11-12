/**
 * setup — one-time policy bootstrap on testnet.
 * creates the sat1 policy and seeds the backend with its view.
 */
import { ShearPinClient } from "@shearpin/sdk";
import { Account, JsonRpcProvider, KeyPairSigner, actions as najActions } from "near-api-js";

const CONTRACT = process.env.SHEARPIN_CONTRACT ?? "";
const OWNER = process.env.SHEARPIN_SIGNER_ID ?? "shearpin-owner.testnet";
const OWNER_KEY = process.env.SHEARPIN_OWNER_KEY ?? "";
const API = process.env.SHEARPIN_API ?? "http://127.0.0.1:8787";
const POLICY_ID = process.env.SHEARPIN_POLICY ?? "sat1";

const TGAS = 10n ** 12n;

async function sendTx(provider: JsonRpcProvider, signer: KeyPairSigner, method: string, args: Record<string, unknown>) {
  const owner = new Account(OWNER, provider, signer);
  const out = (await owner.signAndSendTransaction({
    receiverId: CONTRACT,
    actions: [najActions.functionCall(method, args, BigInt(200) * TGAS, 0n)],
  })) as unknown as { transaction: { hash: string } };
  return out;
}

async function main() {
  if (!CONTRACT || !OWNER_KEY) {
    console.error("set SHEARPIN_CONTRACT and SHEARPIN_OWNER_KEY");
    process.exit(1);
  }
  const provider = new JsonRpcProvider({ url: "https://rpc.testnet.fastnear.com" });
  const signer = KeyPairSigner.fromSecretKey(OWNER_KEY as never);
  const client = new ShearPinClient({
    network: "testnet",
    contractId: CONTRACT,
    signerAccountId: OWNER,
    signerSecretKey: OWNER_KEY,
  });

  console.log("creating policy…");
  await sendTx(provider, signer, "create_policy", {
    policy_id: POLICY_ID,
    agent_label: "SAT-1",
    max_tx: "10000000000000000",     // 0.01 ETH per tx (wei)
    daily_limit: "100000000000000000", // 0.1 ETH per day (wei)
    cooldown_blocks: 2,
    rate_limit_per_day: 20,
  });
  console.log("policy created");

  await sendTx(provider, signer, "set_signer", {
    policy_id: POLICY_ID,
    signer: OWNER,
  });
  console.log("signer set (owner acts as agent runtime for the demo)");

  // the demo vendor is owner-vetted; everything else is unvetted (warn)
  await sendTx(provider, signer, "set_allowed_recipients", {
    policy_id: POLICY_ID,
    recipients: ["0xd4e56740f876afec8011e179a8b763074e6b5c8f"],
  });
  console.log("recipients set (vendor allowlisted)");

  await sendTx(provider, signer, "set_allowed_chain_ids", {
    policy_id: POLICY_ID,
    chain_ids: [11155111], // Sepolia
  });
  console.log("chain ids set (Sepolia only)");

  const view = await client.getPolicy(POLICY_ID);
  console.log("policy view:", view);

  await fetch(`${API}/internal/policy`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      id: POLICY_ID,
      owner: view.owner,
      agent_label: view.agent_label,
      max_tx: view.max_tx,
      daily_limit: view.daily_limit,
      cooldown_blocks: view.cooldown_blocks,
      rate_limit_per_day: view.rate_limit_per_day,
      spent_today: view.spent_today,
      requests_today: view.requests_today,
      tripped: view.tripped,
      frozen: view.frozen,
      status: view.status,
    }),
  }).catch(() => console.log("backend not running — skipped ledger seed (optional)"));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
