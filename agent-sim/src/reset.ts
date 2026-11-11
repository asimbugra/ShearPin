/**
 * reset — unfreezes/resets the pin after a demo run so it can re-run.
 */
import { ShearPinClient } from "@shearpin/sdk";
import { actionCreators, createTransaction, encodeTransaction } from "@near-js/transactions";
import { KeyPairSigner } from "@near-js/signers";
import { JsonRpcProvider } from "@near-js/providers";
import { ethers } from "ethers";

const CONTRACT = process.env.SHEARPIN_CONTRACT ?? "";
const OWNER = process.env.SHEARPIN_SIGNER_ID ?? "shearpin-owner.testnet";
const OWNER_KEY = process.env.SHEARPIN_OWNER_KEY ?? "";
const POLICY_ID = process.env.SHEARPIN_POLICY ?? "sat1";
const API = process.env.SHEARPIN_API ?? "http://127.0.0.1:8787";
const TGAS = 10n ** 12n;

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

  const status = await client.status(POLICY_ID);
  console.log("current status:", status);

  const pubKey = await signer.getPublicKey();
  const accessKey = (await provider.query({
    request_type: "view_access_key",
    account_id: OWNER,
    public_key: pubKey.toString(),
    finality: "optimistic",
  })) as unknown as { nonce: number };
  const block = await provider.block({ finality: "final" });
  const blockHash = ethers.getBytes(Buffer.from(block.header.hash, "base64"));

  const method = status === "tripped" ? "reset_pin" : status === "frozen" ? "unfreeze" : null;
  if (!method) {
    console.log("nothing to reset");
  } else {
    const tx = createTransaction(OWNER, pubKey, CONTRACT, BigInt(accessKey.nonce) + 1n, [
      actionCreators.functionCall(method, { policy_id: POLICY_ID }, BigInt(100) * TGAS, 0n),
    ], blockHash);
    const [, signed] = await signer.signTransaction(tx);
    const bytes = encodeTransaction(signed.transaction);
    const out = await provider.sendJsonRpc("broadcast_tx_commit", [
      Buffer.from(bytes).toString("base64"),
    ]);
    console.log(method, "tx:", (out as { transaction: { hash: string } }).transaction.hash);
  }

  const view = await client.getPolicy(POLICY_ID);
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
  });
  console.log("final status:", view.status);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
