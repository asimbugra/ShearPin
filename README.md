# ShearPin

**One write, every chain off.** — Programmatic spending limits + instant kill-switch for AI agent wallets, powered by NEAR Chain Signatures.

> A shear pin is the mechanical safety device that snaps when torque exceeds the limit — the machine survives. ShearPin does the same for agent wallets: when a spend exceeds policy, the signature is refused. The agent survives; your funds survive.

**Live on NEAR testnet:** `v1.shearpin-owner-2.testnet`  
**Track:** AI Security & Defense — NEAR HACKATHON: Build Beyond Boundaries

---

## The Problem

AI agents that hold wallets can be prompt-injected, hijacked, or simply buggy — and today the only options are "give the agent full key access" or "pre-sign everything by hand."

Existing agent vaults solve this by **imprisoning the agent on a single chain** (access-key escrow on NEAR only). Off-chain relays and custodial guards are bypassable: the agent or an attacker who compromises the relay can reach the key material.

Real incidents show the stakes: prompt-injected agents have been tricked into signing 7-figure transfers because the signing authority lived entirely outside any enforceable boundary.

---

## How It Works

```
┌─────────────┐    1. intent     ┌──────────────────────────┐
│  AI Agent   │ ────────────────▶ │  ShearPin Policy         │
│  (any LLM)  │   RLP unsigned   │  Contract (NEAR)         │
└─────────────┘   EIP-155 tx     │                          │
                                │  ✓ frozen / tripped      │
                                │  ✓ day rollover          │
                                │  ✓ cooldown elapsed      │
                                │  ✓ rate / day not exceeded│
                                │  ✓ chainId allowlist     │
                                │  ✓ calldata: ERC-20 only │
                                │  ✓ recipient allowlist   │
                                │  ✓ amount ≤ max_tx       │
                                │  ✓ spent_today ≤ daily   │
                                │         │                │
                                │  PASS   │ REJECT          │
                                │         ▼                │
                                │  SHEARPIN_* revert       │  ← fail-closed:
                                └────┬─────────────────────┘    no signature, ever
                                     │ 2. MPC sign request
                                     ▼
                       ┌────────────────────────┐
                       │  v1.signer-prod.testnet │
                       │  (NEAR Chain Signatures)│
                       │  MPC network            │
                       └───────────┬────────────┘
                                   │ 3. signature (or nothing)
                                   ▼
                     any EVM chain (per-policy chainId allowlist)
```

The agent submits the **raw RLP-encoded unsigned EIP-155 EVM transaction**. The contract parses it **on-chain** and derives the amount, recipient, and chainId itself — the agent never claims an amount, so it cannot declare "1" while having a large transfer signed. Malformed RLP, unknown calldata, or a non-allowlisted chain/recipient fail closed.

**Control flow (fixed order, fail-closed):**

1. **Frozen** — owner kill-switch active
2. **Tripped** — pin snapped by previous breach
3. **Day rollover** — reset `spent_today`, `requests_today`, per-token counters on new slot
4. **Cooldown** — minimum blocks between requests
5. **Rate limit** — max requests per day
6. **Gas-price cap** — `gasPrice` must be ≤ `max_gas_price` (default 500 gwei); gas burn (`gasPrice × gasLimit`) is charged to the daily budget
7. **Chain allowlist** — `chainId` must be in `allowed_chain_ids` (EIP-155 mandatory; legacy 6-field txs rejected)
8. **Calldata policy** — empty data = native transfer; non-empty must be an ERC-20 `transfer(address,uint256)` (selector `0xa9059cbb`) with `value == 0`, decoded on-chain
9. **Token allowlist** — ERC-20 `to` (token contract) must be in `allowed_tokens` with a per-token cap; token units are tracked in a **separate per-token daily counter**, never mixed with the wei budget
10. **Counterparty blocklist** — shared evidence-backed reports: an address with ≥2 reports is denied (`SHEARPIN_COUNTERPARTY_BLOCKED`) for every policy whose owner has **not** allowlisted it (owner-allowlisted recipients only warn — see the Sybil note below)
11. **Recipient allowlist** — actual recipient (from `to`, or from ERC-20 calldata) must be in `allowed_recipients`
12. **Per-tx cap** — single request cannot exceed `max_tx` (snaps pin on breach)
13. **Daily cap** — cumulative spend + gas burn cannot exceed `daily_limit` (snaps pin on breach)

If **any** check fails, the transaction reverts with a `SHEARPIN_*` error. The MPC network is **never called**. No signature can ever be produced for a denied request.

**Pin mechanism:**
- Per-tx, daily, recipient, or chain breach → `tripped = true` (the pin snaps)
- Owner calls `freeze()` → `frozen = true` (manual kill-switch, same effect)
- Owner calls `reset_pin()` → clears `tripped`, re-arms cooldown
- Owner calls `unfreeze()` → clears `frozen`

**Derivation path isolation:** Every MPC request uses path `shearpin/<policy_id>/<user_path>`. An agent can never sign with another policy's key material.

---

## Threat Model

| Attack | How it's stopped |
|---|---|
| **Amount spoofing** (declare 1, sign 100 ETH) | Amount is parsed on-chain from the RLP `value` field — the agent never claims an amount |
| **Gas-fee drain** (huge gasPrice burns funds) | `max_gas_price` cap per policy; gas burn (`gasPrice × gasLimit`) is charged to the daily budget |
| **Token decimals confusion** (6-decimal USDC vs 18-decimal ETH) | Per-token `allowed_tokens` caps in raw token units — a token not in the list is denied outright |
| **Calldata abuse** (allowlisted contract + `transfer(attacker, all)`) | Calldata must be ERC-20 `transfer`; real recipient + amount are decoded from calldata and run through the same allowlist + caps. Unknown selectors are rejected |
| **Cross-chain replay** (same sig valid everywhere) | EIP-155 `chainId` is mandatory and checked against `allowed_chain_ids`; legacy (pre-EIP-155) txs are rejected |
| **Unauthorized recipient** (attacker address) | Recipient allowlist, fail-closed: empty list denies all |
| **Compromised agent key** (stolen agent NEAR account) | The agent account can only reach `request_signature` — policy gates + caps still apply; `freeze()` stops everything in one write |
| **Rapid-fire drain** (many small txs) | Rate limit per day + cooldown blocks between requests |
| **Buggy agent overspending** | Per-tx cap + daily cap snap the pin; owner resets deliberately |
| **Prompt injection** (attacker tricks the agent into paying a bad address) | Agent-side wrapper runs a counterparty check first: **block** verdict → refuses to sign; on-chain gate enforces it again (`SHEARPIN_COUNTERPARTY_BLOCKED`) even if the wrapper is bypassed |
| **Known-bad counterparty** (reported by other agents) | Shared on-chain blocklist: anyone can `report(address, category, evidence)` with a 0.01 NEAR stake; 2+ evidence-backed reports hard-block the address for every policy whose owner hasn't allowlisted it |
| **Sybil report mob** (two free accounts report your real supplier to snap the pin — a DoS) | Two layers: reports require a **0.01 NEAR stake each** (mass false-reporting burns the *reporter's* money), and an **owner-allowlisted address can never be counterparty-blocked** — reports only warn; the owner re-vets by removing the allowlist entry |

---

## Differentiation

| | Existing agent vaults | **ShearPin** |
|---|---|---|
| Chain coverage | NEAR-only (access keys) | Any EVM chain via Chain Signatures (per-policy `allowed_chain_ids`) |
| Enforcement point | Off-chain relay / server | **On-chain policy contract — before the signature exists** |
| Amount validation | Agent-claimed / relay-checked | **Parsed on-chain from the RLP payload** |
| Calldata validation | None / relay heuristics | **ERC-20 decode + recipient allowlist, on-chain** |
| Kill switch | Re-key dance / revoke | **One transaction: `freeze()`** |
| Trust model | Relay availability / custody | **Contract state, verifiable by anyone** |

The agent gets a real address on any Chain-Signatures-supported chain. But the signing authority sits behind **one NEAR policy contract**: `one write (freeze), every chain off`.

---

## Counterparty Check (allow / warn / block)

Before any payment the agent-side wrapper asks the contract about the receiver:

```
check_counterparty(policy_id, address) -> verdict + reasons
```

- **block** — the address has ≥2 evidence-backed reports on the shared blocklist **and is not in this policy's recipient allowlist**. The wrapper **refuses to sign** (no tx is ever submitted), and the on-chain gate enforces the same verdict (`SHEARPIN_COUNTERPARTY_BLOCKED`, pin snaps) even if the wrapper is bypassed entirely.
- **warn** — something deserves a human look: a single report exists, the address is not in the policy's allowlist (unvetted), or reports exist on an **owner-allowlisted** address. The wrapper calls its `onWarn` hook and only proceeds on explicit human approval. Approval **closes the loop**: with `guardedSpend(req, to, onWarn, { autoAllowApproved: true })` the approving owner's key adds the recipient to the policy allowlist first (`set_allowed_recipients`) — otherwise the on-chain recipient gate would deny the very spend the human just approved. Vet-by-approval, then pay. Live demo: [`docs/warn-approve-demo.log`](docs/warn-approve-demo.log).
- **allow** — allowlisted with zero reports.

**Why allowlisted addresses only warn.** `report()` is permissionless by design — but that makes it a Sybil target: two free testnet accounts could hard-block your real supplier and snap the pin (a DoS). The defense is ownership: **an address the owner explicitly allowlisted can never be counterparty-blocked** — reports only warn, and the owner re-vets by removing the allowlist entry if the reports are credible. Everyone else's blocklist verdict is unchanged.

**The shared blocklist.** Anyone can report a bad counterparty on-chain:

```
report(address, category, evidence)   // evidence (URL or tx hash) is REQUIRED
```

Each report requires an attached deposit of **0.01 NEAR** (`REPORT_DEPOSIT`) — an anti-Sybil stake that pays the report's storage and makes mass false-reporting expensive for the *reporter* (no refunds; spam burns the reporter's money, not the contract's balance). Reports are public, immutable, carry their evidence, one per reporter per address; 2+ reports hard-block the address for every policy that hasn't owner-allowlisted it.

**Attack demo (live, with logs):** a prompt-injected agent is told to pay a known-bad address; the wrapper blocks, the off-chain signal reports are printed alongside (step 1.5, block is never downgraded), and the defense-in-depth on-chain submission is denied with `SHEARPIN_COUNTERPARTY_BLOCKED`. Full log: [`docs/attack-demo.log`](docs/attack-demo.log), script: `agent-sim/attack-demo.mjs`.

**Signals & data sources:**

| Signal | Source | How |
|---|---|---|
| Shared blocklist reports | ShearPin contract state | `check_counterparty` / `get_reports` view calls — on-chain, free |
| Recipient vetted by owner | Policy `allowed_recipients` | same view call; absence → warn |
| Account age & activity | Etherscan V2 API (`ETHERSCAN_API_KEY`) | first-tx timestamp (`txlist` asc) → `< 7 days old` warns; last 25 txs → `low activity` warns |
| Contract vs EOA + code change | `eth_getCode` via `SEPOLIA_RPC` | `"0x"` → EOA; contract code hash compared against the last observation — any change → warn |
| EIP-7702 delegation | same `eth_getCode` call | code starts with `0xef0100…` → the "EOA" delegated to swappable contract code → warn |
| Prior interactions | agent EOA `txlist` (`AGENT_EOA`) | prior successful transfer to the receiver → positive note on the verdict |

The first two rows live **on-chain** (the contract is the source of truth — it can never be downgraded). The rest are the **off-chain enrichment layer** in [`sdk/src/signals.ts`](sdk/src/signals.ts): `enrichCounterparty()` merges them with the contract verdict — **block stays block**; `allow` + any risk signal upgrades to `warn` so a human looks before signing; `warn` gains extra reasons. Every signal degrades gracefully: a missing key, a network error, a timeout or even a malformed RPC response yields a `signal unavailable` note and never a false decision (16 SDK unit tests cover exactly these paths). Wire it in with `guardedSpend(req, recipient, onWarn, { enrich })` — without the option, behavior is unchanged. Code-hash history is pluggable (`codeStore`, default in-process) so a production agent can persist observations in its own store.

For security-critical deployments there is a **fail-closed mode**: `enrich: { failClosed: true }` treats an *unreachable* signal as risk (warn) instead of silently ignored — "couldn't check" should not mean "safe". Default is availability-first (`false`).

---

## The Agent Key (function-call access key, never full access)

The agent NEAR account signs with a **function-call access key scoped to one contract**:

- receiver: the ShearPin contract only
- methods: `request_signature` only
- allowance: **2 NEAR, gas only** — the agent submits its spend with `deposit: 0` (see `sdk/src/index.ts`); the **contract** pays the MPC forwarding deposit from its own balance

What the key cannot do: transfer NEAR, call any other contract, add/delete keys, or delete the account — **or attach deposits at all**. The NEAR protocol rejects a deposit on a function-call-key call (`DepositWithFunctionCall`), so the allowance pays gas only. ShearPin's agent submits its spend with `deposit: 0` (see `sdk/src/index.ts`); the **contract** pays the MPC forwarding deposit from its own balance.

**Allowance caveats** (from the [NEAR access keys docs](https://docs.near.org/protocol/accounts-contracts/access-keys) — read them):

- when the allowance runs out, **the agent locks itself out**. The owner must delete the key and re-add it with a fresh allowance. Provisioning with 2 NEAR makes this a non-event; provisioning with 50 would hide the problem.
- because the **contract pays the MPC deposit**, monitor the *contract's* balance, not the agent's. The per-day rate limit (`rate_limit_per_day`) is the upper bound on that cost.
- an account holding only function-call keys can't transfer NEAR or add keys — it is exactly as narrow as the list above says.

Provision it: `node agent-sim/provision-agent-key.mjs` (creates the agent account with the restricted key — a full-access key is never added). Live end-to-end log — the restricted key runs the counterparty check, gets `allow`, and receives an MPC signature: [`docs/agent-key-demo.log`](docs/agent-key-demo.log).

### Where the agent should run: NEAR AI Cloud + TEE attestation (recommended deployment — not part of this demo)

ShearPin assumes the **host running the LLM can be compromised** — that's what prompt injection means. The design answer is that the runtime never gets trust it can abuse: the signing authority sits behind the on-chain policy contract, and the wrapper's block/warn verdicts are re-checked on-chain (`SHEARPIN_COUNTERPARTY_BLOCKED`) even if the wrapper is bypassed. Deploying the agent on **NEAR AI Cloud** closes the remaining gap at the source: execution runs in a TEE, and the deployment's attestation can be verified per the [NEAR AI Cloud verification docs](https://docs.near.ai/cloud/verification) — so you can confirm the agent code that asked for the signature is the code you audited, not a tampered variant.

---

## Installation

```bash
# 1. Clone and install dependencies
git clone https://github.com/asimbugra/ShearPin.git
cd ShearPin
pnpm install

# 2. Build the smart contract (WASM)
cd contract
cargo test                    # 59 unit tests, all pass
cargo build --target wasm32-unknown-unknown --release
# artifact: target/wasm32-unknown-unknown/release/shearpin_contract.wasm

# 3. Configure environment
cd ..
cp .env.example .env          # fill in SHEARPIN_CONTRACT, SHEARPIN_OWNER_KEY, etc.

# 4. Deploy contract to testnet (requires near-cli-rs or near-api-js deploy script)
cd agent-sim
pnpm build
node --env-file=../.env dist/deploy.js   # deploys wasm + calls new()

# 5. Bootstrap a policy and seed the backend
node --env-file=../.env dist/setup.js    # creates policy "sat1", sets signer,
                                         # sets allowlist + allowed chain IDs

# 6. Start the backend indexer + API
cd ../backend
pnpm build
pnpm start                           # runs on :8787, watches contract events

# 7. Start the frontend dashboard (optional, for visual demo)
cd ../frontend
pnpm build
pnpm dev                             # Vite dev server, proxy to backend

# 8. Run the live 4-scene demo against testnet
cd ../agent-sim
node --env-file=../.env dist/demo.js   # allow → recipient deny+snap → tripped → chain deny
```

> The demo asserts every step: the in-policy spend gets an MPC `signature_ok`
> event, the injected request is denied **before any signature is requested**
> (no `sign:` log in that receipt), the pin stays tripped on-chain until the
> owner calls `reset_pin`, a mainnet-chainId tx is denied by the chain
> allowlist, and every outcome is fed to the backend ledger so the dashboard
> shows the real tx hashes.

---

## Repository Structure

```
contract/          Rust — policy engine + Chain Signatures flow (59 unit tests)
sdk/               TypeScript client SDK (@shearpin/sdk, 13 unit tests)
backend/           Express REST API + SQLite ledger (audit trail)
frontend/          React demo dashboard (breaker panel)
agent-sim/         Demo / setup / deploy / reset scripts (live testnet)
scripts/gen-keys.js  One-time keypair generator for testnet accounts
```

---

## Measured Performance (live testnet)

Measured on the previous `v3.shearpin-owner-1.testnet` deployment (same gate pipeline, NEAR testnet, MPC `v1.signer-prod.testnet`) — raw data in `bench_results.json`, script in `agent-sim/bench2.mjs`. The current deployment reproduces the allow path at ~7.0 s (see `docs/live-demo.log`).

| Path | What happens | Latency | Gas |
|---|---|---|---|
| **Allow** (in-policy spend) | policy check → MPC sign round → `signature_ok` | p50 **6.4 s**, p95 **7.0 s** (n=8, all `signature_ok`) | ~14.1 Tgas |
| **Deny** (over per-tx cap) | policy check → pin snaps (persisted) → **no MPC call at all** | **~1.8–2.0 s** (n=3) | ~2.0 Tgas |

The security story in one number: **denying abuse costs ~7x less gas than a legitimate spend** — the deny path never touches the MPC network.

---

## Live Proof (current deployment: `v1.shearpin-owner-2.testnet`)

Committed logs, captured live on 2026-11-13:

- **[`docs/live-demo.log`](docs/live-demo.log)** — 4-scene demo: in-policy spend **allowed + MPC signature** (~7 s), prompt-injected over-limit payment → `SHEARPIN_RECIPIENT`, pin snaps and **stays tripped** (`SHEARPIN_TRIPPED` on a tiny spend), mainnet-chainId tx → `SHEARPIN_CHAIN`
- **[`docs/attack-demo.log`](docs/attack-demo.log)** — the security story: 2 evidence-backed blocklist reports (owner + an independent reporter, each with the 0.01 NEAR stake) → wrapper verdict **BLOCK → refuses to sign**; the defense-in-depth on-chain submission is denied with `SHEARPIN_COUNTERPARTY_BLOCKED`; the enrichment layer reports EOA detection alongside
- **[`docs/agent-key-demo.log`](docs/agent-key-demo.log)** — the agent account (`sat1-agent.shearpin-owner-2.testnet`) holds **only a function-call key** scoped to `request_signature`; it passes the counterparty check (`allow`) and receives an MPC signature (`signature_ok: YES`)
- **[`docs/warn-approve-demo.log`](docs/warn-approve-demo.log)** — the human-approval loop, closed: unvetted recipient → wrapper **WARN** → the human approves → the owner key adds the recipient to the allowlist → the spend is **allowed** (`SHEARPIN_COUNTERPARTY_BLOCKED` would have fired instead if the address had 2+ reports — the two gates are complementary: the blocklist carries *shared* knowledge across every policy, the allowlist carries *this owner's* vetting)

Earlier proof from the previous `v3` deployment: a [real Sepolia tx](https://sepolia.etherscan.io/tx/0xf88b69bb83d63d02d445a9a6e5d69bceb514ec3a84b275462c14ffde16abc559) — policy-checked on NEAR, MPC-signed, broadcast to Sepolia (`0x33de51b35230a265F48D114e4d923432c597eCb4`, derived from path `shearpin/sat1/eth/0`).

## Limitations (Honest)

- **Testnet only** — contract deployed to `v1.signer-prod.testnet`, not mainnet `v1.signer`
- **EVM-only tx parsing** — the on-chain RLP decoder handles EIP-155 EVM txs; non-EVM chains via Chain Signatures would need their own payload decoders
- **ERC-20 `transfer` only** — `transferFrom`, swaps, and other selectors are rejected fail-closed (adding selectors is a small, contained change)
- **Not audited** — code is hackathon-grade, no formal verification or third-party audit
- **Blocklist has no dispute path** — a false report cannot be removed on-chain (reports are immutable; that's what makes the blocklist credible). The mitigations are economic (0.01 NEAR stake per report, no refunds) and the owner-allowlist override for your own vetted counterparties — but a grieved non-allowlisted address has no on-chain appeal.
- **Report stake is kept, not escrowed** — there is no slashing/reward cycle for correct reporting; the stake only makes spam expensive
- **Single policy per agent** — multi-policy orchestration not implemented
- **Owner is single NEAR account** — no multisig / DAO governance for freeze/reset
- **No slashing / economic security** — MPC network trust is external (NEAR Chain Signatures)

---

## NEAR Hackathon

**Track:** AI Security & Defense  
**Repo:** https://github.com/asimbugra/ShearPin (public, MIT)

---

*ShearPin — the mechanical fuse for agent wallets.*