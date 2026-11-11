// owner-action helper spawned by the backend. receives method + policy id
// via argv so no secrets end up in process listings or logs.
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, actions } from "near-api-js";
import { config } from "dotenv";

const [, , method, policyId] = process.argv;
config({ path: new URL("../.env", import.meta.url).pathname });

const RPC = process.env.SHEARPIN_RPC || "https://rpc.testnet.fastnear.com";
const CONTRACT = process.env.SHEARPIN_CONTRACT;
const OWNER_ID = process.env.SHEARPIN_SIGNER_ID;
const OWNER_KEY = process.env.SHEARPIN_OWNER_KEY;

if (!method || !policyId || !CONTRACT || !OWNER_ID || !OWNER_KEY) {
  console.error("usage: owner-action.mjs <freeze|unfreeze|reset_pin> <policy_id> (+ env)");
  process.exit(2);
}

const provider = new JsonRpcProvider({ url: RPC });
const signer = new KeyPairSigner(KeyPair.fromString(OWNER_KEY));
const acct = new Account(OWNER_ID, provider, signer);

try {
  const res = await acct.signAndSendTransaction({
    receiverId: CONTRACT,
    actions: [actions.functionCall(method, { policy_id: policyId }, 200n * 10n ** 12n, 0n)],
  });
  const logs = [];
  for (const r of res.receipts_outcome ?? []) logs.push(...(r.outcome?.logs ?? []));
  console.log(JSON.stringify({ txHash: res.transaction.hash, logs }));
} catch (e) {
  console.error(String(e));
  process.exit(1);
}
