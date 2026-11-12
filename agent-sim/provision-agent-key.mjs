/**
 * provision the agent account with a FUNCTION-CALL ACCESS KEY scoped to
 * the ShearPin contract only (never a full-access key).
 *
 * what this key CAN do:
 *   - call request_signature() on the ShearPin contract (with a small
 *     attached deposit allowance for the MPC forwarding fee)
 *
 * what it CANNOT do:
 *   - call any other contract
 *   - transfer NEAR, delete the account, add/remove keys
 *   - call owner methods (freeze/reset/set_*) — those require the owner's
 *     key; the contract rejects non-owners anyway
 *
 * even with this key stolen, the thief can only request signatures that
 * pass every on-chain policy gate (caps, allowlists, blocklist, trip).
 *
 * usage: node agent-sim/provision-agent-key.mjs
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, actions } from "near-api-js";
import { config } from "dotenv";

config({ path: "/opt/data/projects/ShearPin/.env" });

const AGENT_ID = process.env.SHEARPIN_AGENT_ID; // e.g. shearpin-agent-1.testnet
const OWNER_ID = process.env.SHEARPIN_SIGNER_ID;
const OWNER_KEY = process.env.SHEARPIN_OWNER_KEY;
const CONTRACT = process.env.SHEARPIN_CONTRACT;
const KEYSTORE = "/opt/data/projects/ShearPin/agent-key.json";

if (!AGENT_ID || !CONTRACT) {
  console.error("SHEARPIN_AGENT_ID / SHEARPIN_CONTRACT must be set");
  process.exit(1);
}

const provider = new JsonRpcProvider({ url: "https://rpc.testnet.fastnear.com" });
const owner = new Account(OWNER_ID, provider, new KeyPairSigner(KeyPair.fromString(OWNER_KEY)));

// 1. generate (or load) the restricted key
let agentKey;
if (existsSync(KEYSTORE)) {
  agentKey = KeyPair.fromString(JSON.parse(readFileSync(KEYSTORE, "utf8")).secret_key);
  console.log("loaded existing function-call key from", KEYSTORE);
} else {
  agentKey = KeyPair.fromRandom("ed25519");
  writeFileSync(KEYSTORE, JSON.stringify({ account_id: AGENT_ID, secret_key: agentKey.toString() }, null, 2), { mode: 0o600 });
  console.log("generated new function-call key ->", KEYSTORE);
}
const pub = agentKey.getPublicKey();

// 2. ensure the agent account exists (created under the owner) with ONLY
//    the function-call key — no full-access key is ever added
try {
  await provider.query({ request_type: "view_account", account_id: AGENT_ID, finality: "final" });
  console.log(AGENT_ID, "exists");
} catch {
  console.log("creating", AGENT_ID, "with function-call key only...");
  await owner.signAndSendTransaction({
    receiverId: AGENT_ID,
    actions: [
      actions.createAccount(),
      actions.transfer(2n * 10n ** 24n), // gas money only
      actions.addFunctionCallAccessKey(
        pub,
        CONTRACT,                     // receiver: ONLY the ShearPin contract
        ["request_signature"],        // methods: ONLY the policy-gated entry point
        50n * 10n ** 24n,             // allowance: 50 NEAR for MPC deposit fees
      ),
    ],
  });
  console.log("agent account created");
}

// 3. verify the key on-chain
const keyInfo = await provider.query({
  request_type: "view_access_key_list",
  account_id: AGENT_ID,
  finality: "final",
});
console.log("keys on", AGENT_ID + ":");
for (const k of keyInfo.keys) {
  const p = k.access_key.permission;
  if ("FunctionCall" in p) {
    console.log("  -", k.public_key, "FUNCTION CALL ONLY ->", p.FunctionCall.receiver_id, JSON.stringify(p.FunctionCall.method_names));
  } else {
    console.log("  -", k.public_key, "FULL ACCESS (!!)");
  }
}
console.log("done. the agent signs with this key; it can do nothing else.");
