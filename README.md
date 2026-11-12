# ShearPin

**One write, every chain off.** — Programmatic spending limits + instant kill-switch for AI agent wallets, powered by NEAR Chain Signatures.

> A shear pin is the mechanical safety device that snaps when torque exceeds the limit — the machine survives. ShearPin does the same for agent wallets: when a spend exceeds policy, the signature is refused. The agent survives; your funds survive.

**Live on NEAR testnet:** `v3.shearpin-owner-1.testnet`  
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
3. **Day rollover** — reset `spent_today`, `requests_today` on new slot
4. **Cooldown** — minimum blocks between requests
5. **Rate limit** — max requests per day
6. **Chain allowlist** — `chainId` must be in `allowed_chain_ids` (EIP-155 mandatory; legacy 6-field txs rejected)
7. **Calldata policy** — empty data = native transfer; non-empty must be an ERC-20 `transfer(address,uint256)` (selector `0xa9059cbb`), decoded on-chain
8. **Recipient allowlist** — actual recipient (from `to`, or from ERC-20 calldata) must be in `allowed_recipients`
9. **Per-tx cap** — single request cannot exceed `max_tx` (snaps pin on breach)
10. **Daily cap** — cumulative spend cannot exceed `daily_limit` (snaps pin on breach)

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

## Installation

```bash
# 1. Clone and install dependencies
git clone https://github.com/asimbugra/ShearPin.git
cd ShearPin
pnpm install

# 2. Build the smart contract (WASM)
cd contract
cargo test                    # 50 unit tests, all pass
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
contract/          Rust — policy engine + Chain Signatures flow (50 unit tests)
sdk/               TypeScript client SDK (@shearpin/sdk)
backend/           Express REST API + SQLite ledger (audit trail)
frontend/          React demo dashboard (breaker panel)
agent-sim/         Demo / setup / deploy / reset scripts (live testnet)
scripts/gen-keys.js  One-time keypair generator for testnet accounts
```

---

## Measured Performance (live testnet)

Measured on `v3.shearpin-owner-1.testnet` (NEAR testnet, MPC `v1.signer-prod.testnet`) — raw data in `bench_results.json`, script in `agent-sim/bench2.mjs`.

| Path | What happens | Latency | Gas |
|---|---|---|---|
| **Allow** (in-policy spend) | policy check → MPC sign round → `signature_ok` | p50 **6.4 s**, p95 **7.0 s** (n=8, all `signature_ok`) | ~14.1 Tgas |
| **Deny** (over per-tx cap) | policy check → pin snaps (persisted) → **no MPC call at all** | **~1.8–2.0 s** (n=3) | ~2.0 Tgas |

The security story in one number: **denying abuse costs ~7x less gas than a legitimate spend** — the deny path never touches the MPC network.

---

## Live Proof

- **On-chain policy verification:** 7-scene demo (allow → recipient deny+snap → tripped containment → chainId deny → ERC-20 calldata recipient deny → **unknown-token deny** → **gas-price-over-cap deny**) executed live against `v3.shearpin-owner-1.testnet`
- **MPC signature + Sepolia broadcast:** [Real Sepolia tx](https://sepolia.etherscan.io/tx/0xf88b69bb83d63d02d445a9a6e5d69bceb514ec3a84b275462c14ffde16abc559) signed via NEAR Chain Signatures, policy-checked on NEAR, broadcast to Sepolia
- **Agent address:** `0x33de51b35230a265F48D114e4d923432c597eCb4` (deterministically derived from path `shearpin/sat1/eth/0`)

## Limitations (Honest)

- **Testnet only** — contract deployed to `v1.signer-prod.testnet`, not mainnet `v1.signer`
- **EVM-only tx parsing** — the on-chain RLP decoder handles EIP-155 EVM txs; non-EVM chains via Chain Signatures would need their own payload decoders
- **ERC-20 `transfer` only** — `transferFrom`, swaps, and other selectors are rejected fail-closed (adding selectors is a small, contained change)
- **Not audited** — code is hackathon-grade, no formal verification or third-party audit
- **Single policy per agent** — multi-policy orchestration not implemented
- **Owner is single NEAR account** — no multisig / DAO governance for freeze/reset
- **No slashing / economic security** — MPC network trust is external (NEAR Chain Signatures)

---

## NEAR Hackathon

**Track:** AI Security & Defense  
**Repo:** https://github.com/asimbugra/ShearPin (public, MIT)

---

*ShearPin — the mechanical fuse for agent wallets.*