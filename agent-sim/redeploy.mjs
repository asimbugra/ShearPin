/** deploy a new wasm to the existing contract account — state is preserved */
import { readFileSync } from "node:fs";
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, actions } from "near-api-js";
import { config } from "dotenv";

config({ path: new URL("../.env", import.meta.url).pathname });

const RPC = process.env.SHEARPIN_RPC || "https://rpc.testnet.fastnear.com";
const OWNER = process.env.SHEARPIN_SIGNER_ID;
const OWNER_KEY = process.env.SHEARPIN_OWNER_KEY;
const CONTRACT = process.env.SHEARPIN_CONTRACT;
const WASM = "/opt/data/projects/ShearPin/contract/target/wasm32-unknown-unknown/release/shearpin_contract.wasm";

const provider = new JsonRpcProvider({ url: RPC });
const owner = new Account(OWNER, provider, new KeyPairSigner(KeyPair.fromString(OWNER_KEY)));

const wasm = readFileSync(WASM);
console.log(`deploying ${wasm.length} bytes to ${CONTRACT} ...`);
// signer account = contract account itself (its FullAccess key) — this is
// how the original deploy did it; signing from the owner fails with
// ActorNoPermission because the key lives on the contract account.
const contract = new Account(CONTRACT, provider, new KeyPairSigner(KeyPair.fromString(OWNER_KEY)));
const out = await contract.signAndSendTransaction({
  receiverId: CONTRACT,
  actions: [actions.deployContract([...wasm])],
});
console.log("DEPLOY:", out.finalExecutionStatus, "tx:", out.transaction.hash);
