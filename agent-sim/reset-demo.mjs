import { Account, JsonRpcProvider, KeyPairSigner, KeyPair, actions } from "near-api-js";
import { config } from "dotenv";
config({ path: new URL("../.env", import.meta.url).pathname, quiet: true });

const TGAS = 10n ** 12n;
const RPC = process.env.SHEARPIN_RPC || "https://rpc.testnet.fastnear.com";
const CONTRACT = process.env.SHEARPIN_CONTRACT;
const OWNER_ID = process.env.SHEARPIN_SIGNER_ID;
const OWNER_KEY = process.env.SHEARPIN_OWNER_KEY;

const ownerKp = KeyPair.fromString(OWNER_KEY);
const ownerSigner = new KeyPairSigner(ownerKp);
const provider = new JsonRpcProvider({ url: RPC });
const ownerAcct = new Account(OWNER_ID, provider, ownerSigner);

async function call(method, args, gas = 200n) {
  return await ownerAcct.signAndSendTransaction({
    receiverId: CONTRACT,
    actions: [actions.functionCall(method, args, gas * TGAS, 0n)],
  });
}

async function main() {
  console.log("Creating fresh policy 'demo2' on", CONTRACT);
  try {
    // max_tx=1000 (0.0001 ETH in wei = 1e14, but contract uses base units - let's use 1000 for demo)
    // daily_limit=3000, cooldown=0, rate=10
    await call("create_policy", {
      policy_id: "demo2",
      agent_label: "SAT-1 procurement agent",
      max_tx: "1000",
      daily_limit: "3000",
      cooldown_blocks: 0,
      rate_limit_per_day: 10,
    }, 200n);
    console.log("Policy demo2 created OK");
  } catch (e) {
    console.log("create_policy:", String(e).slice(0, 120));
  }
  // Set signer for this policy to the agent account
  try {
    await call("set_signer", {
      policy_id: "demo2",
      signer: process.env.SHEARPIN_AGENT_ID,
    }, 200n);
    console.log("Signer set OK");
  } catch (e) {
    console.log("set_signer:", String(e).slice(0, 120));
  }
}
main().catch(console.error);