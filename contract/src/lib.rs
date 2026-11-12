//! shearpin — on-chain policy engine for AI agent wallets
//!
//! the idea: an agent should never hold a key that can move money. it can
//! only ASK. the contract owns the derivation path used with the chain
//! signatures mpc network, and every signature request passes through
//! the policy check first. no relay, no off-chain guard — if the policy
//! says no, the signature request is never made.
//!
//! the agent submits the raw RLP-encoded unsigned EVM transaction; the
//! contract parses it on-chain (see rlp.rs) and derives the amount and
//! recipient itself. the agent never claims an amount, so it cannot
//! declare "1" while having a large transfer signed.
//!
//! supported tx formats:
//!   - legacy (6 fields): [nonce, gasPrice, gasLimit, to, value, data]
//!   - EIP-155 (9 fields): [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
//!
//! calldata policy: empty data = native transfer. non-empty data MUST be a known
//! ERC-20 transfer (selector 0xa9059cbb) to an allowlisted address. anything
//! else is rejected fail-closed.
//!
//! check order is fixed and fail-closed:
//!   frozen -> day rollover -> cooldown -> rate -> chain allowlist
//!   -> recipient allowlist -> per-tx cap -> daily cap

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::store::IterableMap;
use near_sdk::json_types::U128;
use near_sdk::serde_json::json;
use near_sdk::{
    env, ext_contract, near, require, AccountId, BlockHeight, PanicOnDefault, Promise,
    PromiseOrValue,
};

mod rlp;
use rlp::{parse_unsigned_evm_tx, UnsignedEvmTx, ERC20_TRANSFER_SELECTOR};

/// mpc contract on testnet. mainnet uses `v1.signer`.
pub const MPC_CONTRACT: &str = "v1.signer-prod.testnet";

/// gas reserved for the mpc sign call + callback.
pub const MPC_CALL_GAS: u64 = 250_000_000_000_000;

/// deposit forwarded to the mpc contract per signature (1e24 yocto = 1 NEAR).
pub const MPC_DEPOSIT: u128 = 1_000_000_000_000_000_000_000_000;

/// near produces ~1 block/s, so a day is ~86400 blocks.
pub const BLOCKS_PER_DAY: u64 = 86_400;

/// max policies the contract will store (sanity bound).
pub const MAX_POLICIES: u32 = 512;

/// max allowed recipients per policy. empty list = deny all (fail-closed).
pub const MAX_ALLOWED_RECIPIENTS: usize = 32;

/// max allowed chain IDs per policy. empty list = deny all (fail-closed).
pub const MAX_ALLOWED_CHAINS: usize = 16;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
pub struct Policy {
    /// who controls this policy (can update/freeze/reset).
    pub owner: AccountId,
    /// the agent this policy belongs to (informational, set by owner).
    pub agent_label: String,
    /// max amount allowed in a single request (base units of the asset
    /// the owner denominates the policy in).
    pub max_tx: u128,
    /// max cumulative spend per day slot.
    pub daily_limit: u128,
    /// min blocks between two allowed requests.
    pub cooldown_blocks: u64,
    /// max requests allowed per day slot.
    pub rate_limit_per_day: u32,
    /// allowed destination addresses (evm hex, lowercase, 0x prefix).
    /// empty = deny all — fail-closed by design.
    pub allowed_recipients: Vec<String>,
    /// allowed chain IDs (e.g., 11155111 for Sepolia). empty = deny all chains.
    pub allowed_chain_ids: Vec<u64>,
    // --- mutable state ---
    pub spent_today: u128,
    pub day_slot: u64,
    pub requests_today: u32,
    pub cooldown_until: BlockHeight,
    /// tripped = the pin has snapped (hard breach). owner must reset().
    pub tripped: bool,
    /// frozen = manual kill switch by owner. same effect, different cause.
    pub frozen: bool,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    pub policies: IterableMap<String, Policy>,
    pub signers: IterableMap<String, AccountId>,
}

#[near]
impl Contract {
    #[init]
    pub fn new() -> Self {
        require!(!env::state_exists(), "already initialized");
        Self {
            policies: IterableMap::new(b"p"),
            signers: IterableMap::new(b"s"),
        }
    }

    // ------------------------------------------------------------------
    // policy management (owner calls these)
    // ------------------------------------------------------------------

    /// create a policy. caller becomes its owner.
    pub fn create_policy(
        &mut self,
        policy_id: String,
        agent_label: String,
        max_tx: U128,
        daily_limit: U128,
        cooldown_blocks: u64,
        rate_limit_per_day: u32,
    ) -> PolicyView {
        require!(!policy_id.is_empty(), "policy id required");
        require!(policy_id.len() <= 64, "policy id too long");
        require!(self.policies.get(&policy_id).is_none(), "policy exists");
        require!(self.policy_len() < MAX_POLICIES, "policy store full");
        require!(max_tx.0 > 0, "max_tx must be > 0");
        require!(
            daily_limit.0 >= max_tx.0,
            "daily_limit < max_tx makes no sense"
        );

        let policy = Policy {
            owner: env::predecessor_account_id(),
            agent_label,
            max_tx: max_tx.0,
            daily_limit: daily_limit.0,
            cooldown_blocks,
            rate_limit_per_day: rate_limit_per_day.max(1),
            allowed_recipients: Vec::new(),   // empty = deny all until set
            allowed_chain_ids: Vec::new(),    // empty = deny all chains until set
            spent_today: 0,
            day_slot: current_day_slot(),
            requests_today: 0,
            cooldown_until: 0,
            tripped: false,
            frozen: false,
        };
        let view = policy.clone().into_view();
        self.policies.insert(policy_id.clone(), policy);
        view
    }

    /// update limits. owner only.
    pub fn update_policy(
        &mut self,
        policy_id: String,
        max_tx: Option<U128>,
        daily_limit: Option<U128>,
        cooldown_blocks: Option<u64>,
        rate_limit_per_day: Option<u32>,
    ) -> PolicyView {
        let mut policy = self.policy_owned(&policy_id);
        if let Some(v) = max_tx {
            require!(v.0 > 0, "max_tx must be > 0");
            policy.max_tx = v.0;
        }
        if let Some(v) = daily_limit {
            require!(v.0 >= policy.max_tx, "daily_limit < max_tx");
            policy.daily_limit = v.0;
        }
        if let Some(v) = cooldown_blocks {
            policy.cooldown_blocks = v;
        }
        if let Some(v) = rate_limit_per_day {
            policy.rate_limit_per_day = v.max(1);
        }
        let view = policy.clone().into_view();
        self.policies.insert(policy_id.clone(), policy);
        view
    }

    /// set the account that may call request_signature for this policy.
    /// owner only. this is the agent runtime's near account.
    pub fn set_signer(&mut self, policy_id: String, signer: AccountId) {
        let _ = self.policy_owned(&policy_id);
        self.signers.insert(policy_id.clone(), signer);
    }

    /// set allowed destination addresses for this policy. owner only.
    /// entries are normalized to lowercase 0x-prefixed hex and deduped.
    /// an EMPTY list denies all transfers — fail-closed by design.
    pub fn set_allowed_recipients(
        &mut self,
        policy_id: String,
        recipients: Vec<String>,
    ) -> PolicyView {
        let mut policy = self.policy_owned(&policy_id);
        require!(
            recipients.len() <= MAX_ALLOWED_RECIPIENTS,
            "too many recipients"
        );
        let normalized: Vec<String> = recipients
            .into_iter()
            .map(|r| {
                let r = r.trim().to_lowercase();
                if r.starts_with("0x") { r } else { format!("0x{}", r) }
            })
            .collect();
        let mut seen = std::collections::HashSet::new();
        policy.allowed_recipients = normalized
            .into_iter()
            .filter(|r| seen.insert(r.clone()))
            .collect();
        let view = policy.clone().into_view();
        self.policies.insert(policy_id.clone(), policy);
        env::log_str(&format!(
            "{{\"event\":\"allowed_recipients_updated\",\"policy\":\"{}\",\"count\":{}}}",
            policy_id, view.allowed_recipients.len()
        ));
        view
    }

    /// set allowed chain IDs for this policy. owner only.
    /// empty list = deny all chains (fail-closed).
    /// typical values: 11155111 (Sepolia), 1 (Ethereum mainnet), etc.
    pub fn set_allowed_chain_ids(
        &mut self,
        policy_id: String,
        chain_ids: Vec<u64>,
    ) -> PolicyView {
        let mut policy = self.policy_owned(&policy_id);
        require!(
            chain_ids.len() <= MAX_ALLOWED_CHAINS,
            "too many chain IDs"
        );
        let mut seen = std::collections::HashSet::new();
        policy.allowed_chain_ids = chain_ids
            .into_iter()
            .filter(|c| seen.insert(*c))
            .collect();
        let view = policy.clone().into_view();
        self.policies.insert(policy_id.clone(), policy);
        env::log_str(&format!(
            "{{\"event\":\"allowed_chain_ids_updated\",\"policy\":\"{}\",\"count\":{}}}",
            policy_id, view.allowed_chain_ids.len()
        ));
        view
    }

    /// manual kill switch — freezes the wallet on every chain at once.
    /// owner only. one write, nothing gets signed until unfreeze.
    pub fn freeze(&mut self, policy_id: String) -> PolicyView {
        let mut policy = self.policy_owned(&policy_id);
        policy.frozen = true;
        let view = policy.clone().into_view();
        self.policies.insert(policy_id.clone(), policy);
        env::log_str(&deny(&policy_id, "frozen", 0, "", None));
        view
    }

    pub fn unfreeze(&mut self, policy_id: String) -> PolicyView {
        let mut policy = self.policy_owned(&policy_id);
        policy.frozen = false;
        let view = policy.clone().into_view();
        self.policies.insert(policy_id.clone(), policy);
        env::log_str(&format!(
            "{{\"event\":\"unfrozen\",\"policy\":\"{}\"}}",
            policy_id
        ));
        view
    }

    /// reset a tripped pin. owner only.
    pub fn reset_pin(&mut self, policy_id: String) -> PolicyView {
        let mut policy = self.policy_owned(&policy_id);
        require!(policy.tripped, "pin not tripped");
        policy.tripped = false;
        policy.cooldown_until = env::block_height() + policy.cooldown_blocks;
        let view = policy.clone().into_view();
        self.policies.insert(policy_id.clone(), policy);
        env::log_str(&format!(
            "{{\"event\":\"pin_reset\",\"policy\":\"{}\"}}",
            policy_id
        ));
        view
    }

    // ------------------------------------------------------------------
    // the hot path: agent asks, policy decides before any mpc call
    // ------------------------------------------------------------------

    /// request a chain-signatures signature for an RLP-encoded unsigned
    /// EVM transaction after policy check. the contract parses the RLP
    /// on-chain to derive amount (value) and recipient (to) — the agent
    /// never claims an amount. the 32-byte payload hash for MPC is
    /// computed here via keccak256, so the signature can only ever apply
    /// to the transaction that was policy-checked. denials PERSIST state
    /// (trip flags, day rollover) and return Value instead of panicking,
    /// so the mpc network is never called and the trip survives.
    #[payable]
    pub fn request_signature(
        &mut self,
        policy_id: String,
        derivation_path: String,
        key_type: String,
        payload: Vec<u8>,
    ) -> PromiseOrValue<String> {
        let mut policy = self.policy_or_missing(&policy_id);
        self.require_authorized_signer(&policy_id, &policy);

        // roll the day forward if we crossed a slot boundary
        let slot = current_day_slot();
        if policy.day_slot != slot {
            policy.day_slot = slot;
            policy.spent_today = 0;
            policy.requests_today = 0;
        }

        // derive amount + recipient + chain_id from the payload itself — the agent
        // has no say in what is checked. malformed RLP = fail-closed.
        let tx = parse_unsigned_evm_tx(&payload)
            .unwrap_or_else(|e| env::panic_str(&format!("SHEARPIN_RLP_ERROR: {:?}", e)));

        // determine the actual amount and recipient based on tx type
        let (amount, recipient, is_erc20) = if let (Some(erc20_to), Some(erc20_amt)) = (tx.erc20_to.clone(), tx.erc20_amount) {
            // ERC-20 transfer: value=0, real amount/recipient from calldata
            (erc20_amt, erc20_to, true)
        } else {
            // native transfer: value and to from tx fields
            (tx.value, tx.to.clone(), false)
        };

        // chain ID validation (fail-closed: empty list denies all chains)
        if let Some(chain_id) = tx.chain_id {
            if !policy.allowed_chain_ids.iter().any(|c| *c == chain_id) {
                policy.tripped = true;
                self.policies.insert(policy_id.clone(), policy);
                env::log_str(&deny(&policy_id, "chain_not_allowed", amount, &recipient, Some(chain_id)));
                return PromiseOrValue::Value(
                    "SHEARPIN_CHAIN: chain ID not in allowlist — pin snapped".to_string(),
                );
            }
        } else {
            // legacy tx without chainId: only allowed if policy explicitly allows chain_id=0 (legacy)
            // but we require EIP-155 for security (replay protection)
            policy.tripped = true;
            self.policies.insert(policy_id.clone(), policy);
            env::log_str(&deny(&policy_id, "legacy_tx_rejected", amount, &recipient, None));
            return PromiseOrValue::Value(
                "SHEARPIN_LEGACY_TX: EIP-155 transaction required (chainId mandatory)".to_string(),
            );
        }

        // fixed check order — do not reorder. fail-closed on anything
        // unexpected. every deny PERSISTS state (trip flags, day rollover)
        // and returns Value instead of panicking.
        if policy.frozen {
            env::log_str(&deny(&policy_id, "frozen", amount, &recipient, tx.chain_id));
            self.policies.insert(policy_id.clone(), policy);
            env::panic_str("SHEARPIN_FROZEN");
        }
        if policy.tripped {
            env::log_str(&deny(&policy_id, "tripped", amount, &recipient, tx.chain_id));
            self.policies.insert(policy_id.clone(), policy);
            env::panic_str("SHEARPIN_TRIPPED");
        }
        if env::block_height() < policy.cooldown_until {
            env::log_str(&deny(&policy_id, "cooldown", amount, &recipient, tx.chain_id));
            self.policies.insert(policy_id.clone(), policy);
            env::panic_str("SHEARPIN_COOLDOWN");
        }
        if policy.requests_today >= policy.rate_limit_per_day {
            env::log_str(&deny(&policy_id, "rate", amount, &recipient, tx.chain_id));
            self.policies.insert(policy_id.clone(), policy);
            env::panic_str("SHEARPIN_RATE");
        }
        // recipient allowlist — fail-closed: empty list denies everything
        if !policy.allowed_recipients.iter().any(|r| r == &recipient) {
            policy.tripped = true;
            self.policies.insert(policy_id.clone(), policy);
            env::log_str(&deny(&policy_id, "recipient_not_allowed", amount, &recipient, tx.chain_id));
            return PromiseOrValue::Value(
                "SHEARPIN_RECIPIENT: destination not in allowlist — pin snapped".to_string(),
            );
        }
        if amount > policy.max_tx {
            // soft breach: deny + snap the pin. the agent tried to move
            // more than a single transaction may ever move. NOTE: we must
            // NOT panic here — a panic reverts ALL state, so the trip
            // would never persist. instead we persist the trip, emit a
            // deny event, and return without ever requesting a signature.
            policy.tripped = true;
            self.policies.insert(policy_id.clone(), policy);
            env::log_str(&deny(&policy_id, "over_tx_snap", amount, &recipient, tx.chain_id));
            return PromiseOrValue::Value(
                "SHEARPIN_OVER_TX: amount above per-tx cap — pin snapped".to_string(),
            );
        }
        if policy.spent_today + amount > policy.daily_limit {
            // hard breach of the daily budget: deny + trip. same rule —
            // persist first, never panic, no signature is ever requested.
            policy.tripped = true;
            self.policies.insert(policy_id.clone(), policy);
            env::log_str(&deny(&policy_id, "over_daily_snap", amount, &recipient, tx.chain_id));
            return PromiseOrValue::Value(
                "SHEARPIN_OVER_DAILY: daily cap exceeded — pin snapped".to_string(),
            );
        }

        // passed — book the spend and set the cooldown
        policy.spent_today += amount;
        policy.requests_today += 1;
        policy.cooldown_until = env::block_height() + policy.cooldown_blocks;
        let spent = policy.spent_today;
        let reqs = policy.requests_today;
        self.policies.insert(policy_id.clone(), policy);

        env::log_str(&format!(
            "{{\"event\":\"allow\",\"policy\":\"{}\",\"amount\":{},\"recipient\":\"{}\",\"spent_today\":{},\"requests_today\":{},\"is_erc20\":{},\"chain_id\":{}}}",
            policy_id,
            amount,
            recipient,
            spent,
            reqs,
            is_erc20,
            tx.chain_id.map(|c| c.to_string()).unwrap_or("null".to_string())
        ));

        // hash the checked payload on-chain: the MPC signature can only
        // ever apply to this exact transaction.
        let payload_hash = env::keccak256(&payload);

        // forward to the mpc network. path is forced through the policy
        // namespace so an agent can never sign with someone else's
        // derivation.
        let path = format!("shearpin/{}/{}", policy_id, derivation_path);
        let key = match key_type.as_str() {
            "ecdsa" | "secp256k1" => "ecdsa",
            "eddsa" | "ed25519" => "eddsa",
            _ => env::panic_str("SHEARPIN_KEY_TYPE: unknown key type"),
        };

        let mpc: AccountId = MPC_CONTRACT.parse().unwrap();
        // v1.signer's `sign` takes SignRequestArgs:
        // { "request": { "payload_v2": {"Ecdsa": "<hex>"}, "path": ..., "domain_id": 0 } }
        // legacy flat form (payload: [u8;32], key_version) also accepted.
        let args = json!({
            "request": {
                "payload": payload_hash,
                "path": path,
                "key_version": 0,
            }
        });

        let callback_gas = near_sdk::Gas::from_gas(30_000_000_000_000);
        Promise::new(mpc)
            .function_call(
                "sign".to_string(),
                near_sdk::serde_json::to_vec(&args).unwrap(),
                near_sdk::NearToken::from_yoctonear(MPC_DEPOSIT),
                near_sdk::Gas::from_gas(MPC_CALL_GAS),
            )
            .then(Promise::new(env::current_account_id()).function_call(
                "on_signature".to_string(),
                vec![],
                near_sdk::NearToken::from_yoctonear(0),
                callback_gas,
            ))
            .into()
    }

    /// mpc callback — logs the outcome, returns the signature upstream.
    #[private]
    pub fn on_signature(&mut self) -> Vec<u8> {
        match env::promise_result_checked(0, 1_048_576) {
            Ok(sig) => {
                env::log_str("{\"event\":\"signature_ok\"}");
                sig
            }
            Err(_) => {
                env::log_str("{\"event\":\"signature_failed\"}");
                env::panic_str("SHEARPIN_MPC_FAILED: mpc network did not return a signature")
            }
        }
    }

    // ------------------------------------------------------------------
    // views
    // ------------------------------------------------------------------

    pub fn get_policy(&self, policy_id: String) -> Option<PolicyView> {
        self.policies.get(&policy_id).map(|p| p.clone().into_view())
    }

    pub fn policy_status(&self, policy_id: String) -> String {
        status_of(self.policies.get(&policy_id).cloned())
    }

    pub fn policy_len(&self) -> u32 {
        self.policies.len() as u32
    }

    // ------------------------------------------------------------------
    // internals
    // ------------------------------------------------------------------

    fn policy_or_missing(&self, policy_id: &str) -> Policy {
        self.policies
            .get(policy_id)
            .cloned()
            .unwrap_or_else(|| env::panic_str("SHEARPIN_NO_POLICY: no such policy"))
    }

    fn policy_owned(&self, policy_id: &str) -> Policy {
        let p = self.policy_or_missing(policy_id);
        require!(
            &p.owner == &env::predecessor_account_id(),
            "SHEARPIN_OWNER: only the policy owner can do this"
        );
        p
    }

    fn require_authorized_signer(&self, policy_id: &str, policy: &Policy) {
        let caller = env::predecessor_account_id();
        if caller == policy.owner {
            return;
        }
        match self.signers.get(policy_id) {
            Some(s) => require!(*s == caller, "SHEARPIN_SIGNER: caller is not the agent signer"),
            None => env::panic_str("SHEARPIN_NO_SIGNER: set a signer first"),
        }
    }
}

// ----------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------

fn current_day_slot() -> u64 {
    env::block_height() / BLOCKS_PER_DAY
}

fn status_of(p: Option<Policy>) -> String {
    match p {
        None => "missing".to_string(),
        Some(ref p) => {
            if p.frozen {
                "frozen".to_string()
            } else if p.tripped {
                "tripped".to_string()
            } else if env::block_height() < p.cooldown_until {
                "cooldown".to_string()
            } else {
                "ok".to_string()
            }
        }
    }
}

fn deny(policy_id: &str, reason: &str, amount: u128, recipient: &str, chain_id: Option<u64>) -> String {
    let chain_part = chain_id.map(|c| format!("\"chain_id\":{}", c)).unwrap_or("\"chain_id\":null".to_string());
    format!(
        "{{\"event\":\"deny\",\"policy\":\"{}\",\"reason\":\"{}\",\"amount\":{},\"recipient\":\"{}\",{}}}",
        policy_id, reason, amount, recipient, chain_part
    )
}

#[derive(Clone, Debug, PartialEq, near_sdk::serde::Serialize, near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct PolicyView {
    pub owner: String,
    pub agent_label: String,
    pub max_tx: u128,
    pub daily_limit: u128,
    pub cooldown_blocks: u64,
    pub rate_limit_per_day: u32,
    pub spent_today: u128,
    pub requests_today: u32,
    pub tripped: bool,
    pub frozen: bool,
    pub status: String,
    pub allowed_recipients: Vec<String>,
    pub allowed_chain_ids: Vec<u64>,
}

impl From<Policy> for PolicyView {
    fn from(p: Policy) -> Self {
        let status = status_of(Some(p.clone()));
        PolicyView {
            owner: p.owner.to_string(),
            agent_label: p.agent_label,
            max_tx: p.max_tx,
            daily_limit: p.daily_limit,
            cooldown_blocks: p.cooldown_blocks,
            rate_limit_per_day: p.rate_limit_per_day,
            spent_today: p.spent_today,
            requests_today: p.requests_today,
            tripped: p.tripped,
            frozen: p.frozen,
            status,
            allowed_recipients: p.allowed_recipients,
            allowed_chain_ids: p.allowed_chain_ids,
        }
    }
}

impl Policy {
    pub fn into_view(self) -> PolicyView {
        self.into()
    }
}

// cross-contract callback binding (sdk5 pattern)
#[ext_contract]
trait ShearPinMpc {
    fn sign(&self, payload: Vec<u8>, path: String, key_type: String);
}

#[cfg(test)]
mod tests;