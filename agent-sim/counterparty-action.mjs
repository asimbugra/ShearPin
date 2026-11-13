// counterparty-action helper spawned by the backend.
//   enrich <address> <policy_id>            — SDK signal enrichment (no keys on argv)
//   report  <address> <category> <evidence> — owner signs report() + 0.01 NEAR stake
// prints a single JSON line on stdout as the LAST line.
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, actions } from "near-api-js";
import { config } from "dotenv";

const [, , mode, a1, a2, a3] = process.argv;
config({ path: new URL("../.env", import.meta.url).pathname, quiet: true });

const RPC = process.env.SHEARPIN_RPC || "https://rpc.testnet.fastnear.com";
const CONTRACT = process.env.SHEARPIN_CONTRACT;
const OWNER_ID = process.env.SHEARPIN_SIGNER_ID;
const OWNER_KEY = process.env.SHEARPIN_OWNER_KEY;
const POLICY = process.env.SHEARPIN_POLICY || "sat1";
const TGAS = 10n ** 12n;

if (!CONTRACT || !OWNER_ID || !OWNER_KEY || !a1) {
  console.error("usage: counterparty-action.mjs <enrich|report> <address> [policy|category] [evidence] (+ env)");
  process.exit(2);
}

const provider = new JsonRpcProvider({ url: RPC });

async function view(method, args) {
  const res = await provider.query({
    request_type: "call_function",
    account_id: CONTRACT,
    method_name: method,
    args_base64: Buffer.from(JSON.stringify(args)).toString("base64"),
    finality: "final",
  });
  return JSON.parse(Buffer.from(res.result).toString("utf8"));
}

try {
  if (mode === "enrich") {
    const address = a1;
    const policyId = a2 || POLICY;
    const { enrichCounterparty } = await import("@shearpin/sdk");
    const out = await enrichCounterparty(
      {
        checkCounterparty: async (policy, addr) => {
          const [v, r] = await view("check_counterparty", { policy_id: policy, address: addr });
          return { verdict: v, reasons: r };
        },
      },
      policyId,
      address,
      {
        etherscanApiKey: process.env.ETHERSCAN_API_KEY,
        etherscanApiUrl: process.env.ETHERSCAN_API_URL || "https://api.etherscan.io/v2/api",
        chainId: Number(process.env.ETHERSCAN_CHAIN_ID || 11155111),
        evmRpcUrl: process.env.SEPOLIA_RPC,
        agentEoa: process.env.AGENT_EOA,
        timeoutMs: 8000,
      },
    );
    console.log(JSON.stringify(out));
  } else if (mode === "report") {
    const address = a1;
    const category = a2;
    const evidence = a3;
    if (!category || !evidence) {
      console.error("report mode needs <address> <category> <evidence>");
      process.exit(2);
    }
    // pre-checks so failures come back as clean messages, not wasm traps
    const existing = await view("get_reports", { address });
    if (existing.some((r) => r.reporter === OWNER_ID)) {
      console.error("already reported by this account");
      process.exit(3);
    }
    if (existing.length >= 32) {
      console.error("report cap reached");
      process.exit(3);
    }
    const signer = new KeyPairSigner(KeyPair.fromString(OWNER_KEY));
    const acct = new Account(OWNER_ID, provider, signer);
    const res = await acct.signAndSendTransaction({
      receiverId: CONTRACT,
      actions: [actions.functionCall("report", { address, category, evidence }, 100n * TGAS, 10n ** 22n)],
    });
    const logs = [];
    for (const r of res.receipts_outcome ?? []) logs.push(...(r.outcome?.logs ?? []));
    console.log(JSON.stringify({ txHash: res.transaction.hash, logs }));
  } else {
    console.error(`unknown mode: ${mode}`);
    process.exit(2);
  }
} catch (e) {
  console.error(String(e));
  process.exit(1);
}
