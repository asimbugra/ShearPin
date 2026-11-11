/**
 * deploy — creates the contract account (if needed) and deploys the wasm
 * in one batched transaction from the owner, via near-api-js v7.
 *
 * batch: createAccount + transfer(3Ⓝ) + addKey(owner full-access)
 *        + deployContract(wasm) + functionCall(new)
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Account, JsonRpcProvider, KeyPairSigner, actions as najActions } from "near-api-js";

const RPC = process.env.SHEARPIN_RPC ?? "https://rpc.testnet.fastnear.com";
const OWNER = process.env.SHEARPIN_SIGNER_ID ?? "";
const OWNER_KEY = process.env.SHEARPIN_OWNER_KEY ?? "";
const CONTRACT = process.env.SHEARPIN_CONTRACT ?? "";
const WASM = process.env.SHEARPIN_WASM ?? resolve(process.cwd(), "../contract/target/wasm32-unknown-unknown/release/shearpin_contract.wasm");
const TGAS = 10n ** 12n;

async function main() {
  if (!CONTRACT || !OWNER || !OWNER_KEY) {
    console.error("set SHEARPIN_CONTRACT / SHEARPIN_SIGNER_ID / SHEARPIN_OWNER_KEY");
    process.exit(1);
  }
  const provider = new JsonRpcProvider({ url: RPC });
  const signer = KeyPairSigner.fromSecretKey(OWNER_KEY as never);
  const owner = new Account(OWNER, provider, signer);
  const pubKey = await signer.getPublicKey();

  const exists = await provider
    .query({ request_type: "view_account", finality: "final", account_id: CONTRACT })
    .then(() => true)
    .catch(() => false);

  const code = new Uint8Array(readFileSync(WASM));
  console.log(`wasm: ${WASM} (${code.length} bytes)`);
  console.log(`contract account exists: ${exists}`);

  const actions = exists
    ? [
        najActions.deployContract(code),
      ]
    : [
        najActions.createAccount(),
        najActions.transfer(5n * 10n ** 24n),
        najActions.addFullAccessKey(pubKey),
        najActions.deployContract(code),
        najActions.functionCall("new", {}, BigInt(100) * TGAS, 0n),
      ];

  const out = (await (exists
    ? new Account(CONTRACT, provider, signer)
    : new Account(OWNER, provider, signer)
  ).signAndSendTransaction({
    receiverId: CONTRACT,
    actions,
  })) as unknown as {
    transaction: { hash: string };
    receipts_outcome?: { outcome: { logs?: string[] } }[];
  };
  const logs: string[] = [];
  for (const r of out.receipts_outcome ?? []) logs.push(...(r.outcome?.logs ?? []));
  console.log("deploy tx:", out.transaction.hash);
  console.log("logs:", logs);
}
main().catch((e) => { console.error(e); process.exit(1); });
