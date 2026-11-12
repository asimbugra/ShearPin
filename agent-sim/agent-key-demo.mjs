/** end-to-end: the RESTRICTED function-call key requests a signature */
import { readFileSync } from "node:fs";
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, actions } from "near-api-js";
import { config } from "dotenv";
config({ path: "/opt/data/projects/ShearPin/.env" });
const provider = new JsonRpcProvider({ url: "https://rpc.testnet.fastnear.com" });
const keyJson = JSON.parse(readFileSync("/opt/data/projects/ShearPin/agent-key.json", "utf8"));
const agent = new Account(keyJson.account_id, provider, new KeyPairSigner(KeyPair.fromString(keyJson.secret_key)));
console.log("signing as:", keyJson.account_id, "(function-call key only)");

// the vendor payment from S1 (allow path)
function encodeInt(v) {
  if (v === 0n) return [0x80];
  const bytes = []; let x = v;
  while (x > 0n) { bytes.unshift(Number(x & 0xffn)); x >>= 8n; }
  if (bytes.length === 1 && bytes[0] <= 0x7f) return bytes;
  return [0x80 + bytes.length, ...bytes];
}
function toBytes(hex) { const h = hex.replace("0x",""); const o=[]; for(let i=0;i<h.length;i+=2)o.push(parseInt(h.slice(i,i+2),16)); return o; }
const VENDOR = "0xd4e56740f876afec8011e179a8b763074e6b5c8f";
const items = [
  encodeInt(20n), encodeInt(20_000_000_000n), encodeInt(21_000n),
  [0x94, ...toBytes(VENDOR)], encodeInt(1_000_000_000n), [0x80],
  encodeInt(11155111n), encodeInt(0n), encodeInt(0n),
];
const inner = items.flat();
const payload = [0xc0 + inner.length, ...inner];

// counterparty check first (wrapper behavior)
const res = await provider.query({
  request_type: "call_function",
  account_id: "v3.shearpin-owner-1.testnet",
  method_name: "check_counterparty",
  args_base64: Buffer.from(JSON.stringify({ policy_id: "sat1", address: VENDOR })).toString("base64"),
  finality: "final",
});
const [verdict] = JSON.parse(Buffer.from(res.result).toString("utf8"));
console.log("counterparty verdict:", verdict);
if (verdict === "block") { console.log("REFUSED"); process.exit(0); }

let out;
try {
  out = await agent.signAndSendTransaction({
  receiverId: "v3.shearpin-owner-1.testnet",
  actions: [actions.functionCall("request_signature", { policy_id: "sat1", derivation_path: "eth/0", key_type: "ecdsa", payload }, 300n * 10n ** 12n, 0n)],
  });
} catch (err) {
  const logs = (err.transactionResult?.receipts_outcome ?? []).flatMap((r) => r.outcome?.logs ?? []);
  console.log("deny logs:", logs.filter((l) => l.includes("deny") || l.includes("event")));
  const m = (err.message ?? "").match(/SHEARPIN_[A-Z_]+|panicked at [^\n]+/);
  console.log("panic:", m?.[0] ?? (err.message ?? "").slice(0, 150));
  process.exit(1);
}
const logs = (out.receipts_outcome ?? []).flatMap((r) => r.outcome?.logs ?? []);
console.log("allow log:", logs.find((l) => l.includes('"event":"allow"')) ?? "none");
console.log("signature_ok:", logs.some((l) => l.includes("signature_ok")) ? "YES" : "pending (async mpc)");
console.log("AGENT KEY END-TO-END: signature requested with the restricted key only");
