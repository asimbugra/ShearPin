import { JsonRpcProvider } from "near-api-js";
import { config } from "dotenv";
config({ path: new URL("../.env", import.meta.url).pathname, quiet: true });
const provider = new JsonRpcProvider({ url: process.env.SHEARPIN_RPC });
const CONTRACT = process.env.SHEARPIN_CONTRACT;
for (const pid of ["sat1", "demo2"]) {
  const raw = await provider.query({
    request_type: "call_function",
    finality: "final",
    account_id: CONTRACT,
    method_name: "get_policy",
    args_base64: Buffer.from(JSON.stringify({ policy_id: pid })).toString("base64"),
  });
  const p = JSON.parse(Buffer.from(raw.result).toString());
  console.log(pid, "→", JSON.stringify(p));
  if (p) {
    await fetch("http://127.0.0.1:8787/internal/policy", {
      method: "POST", headers: { "content-type": "application/json", ...(process.env.SHEARPIN_ADMIN_TOKEN ? { Authorization: `Bearer ${process.env.SHEARPIN_ADMIN_TOKEN}` } : {}) },
      body: JSON.stringify({ id: pid, owner: p.owner, agent_label: p.agent_label, max_tx: p.max_tx, daily_limit: p.daily_limit, cooldown_blocks: p.cooldown_blocks, rate_limit_per_day: p.rate_limit_per_day, spent_today: p.spent_today, requests_today: p.requests_today, tripped: p.tripped, frozen: p.frozen, status: p.status }),
    });
  }
}
