//! unit tests — every policy rule, boundaries, fail-closed paths

use crate::*;
use crate::rlp::parse_unsigned_legacy_tx;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{testing_env, AccountId, VMContext};

fn alice() -> AccountId {
    "alice.near".parse().unwrap()
}

fn bob() -> AccountId {
    "bob.near".parse().unwrap()
}

fn base_ctx() -> VMContext {
    let mut b = VMContextBuilder::new();
    b.predecessor_account_id(alice())
        .block_index(1_000_000_000);
    b.build()
}

fn fresh() -> Contract {
    Contract::new()
}

fn make_policy(c: &mut Contract, id: &str, max_tx: u128, daily: u128) {
    c.create_policy(id.into(), "sat-1".into(), U128(max_tx), U128(daily), 10, 5);
}

/// the canonical test vendor address (also the default allowlist entry)
const VENDOR: &str = "0xd4e56740f876afec8011e179a8b763074e6b5c8f";

/// build a canonical RLP-encoded unsigned legacy EVM tx
/// nonce=1, gasPrice=20 gwei, gasLimit=21000, to=VENDOR, value=amount, data=""
fn make_rlp_tx(amount: u128) -> Vec<u8> {
    make_rlp_tx_to_addr(VENDOR, amount)
}

/// same, but with an arbitrary recipient (hex string with 0x prefix)
fn make_rlp_tx_to_addr(to_hex: &str, amount: u128) -> Vec<u8> {
    // decode hex address to bytes
    let hex = to_hex.trim_start_matches("0x");
    let mut to_bytes = vec![];
    for i in (0..hex.len()).step_by(2) {
        to_bytes.push(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
    }
    assert_eq!(to_bytes.len(), 20);

    let value_item: Vec<u8> = if amount == 0 {
        vec![0x80]
    } else {
        let mut bytes = vec![];
        let mut v = amount;
        while v > 0 {
            bytes.push((v & 0xff) as u8);
            v >>= 8;
        }
        bytes.reverse();
        let mut item = vec![0x80 + bytes.len() as u8];
        item.extend(bytes);
        item
    };

    let mut inner: Vec<u8> = vec![];
    inner.push(0x01);                                     // nonce=1
    inner.extend([0x85, 0x04, 0xa8, 0x17, 0xc8, 0x00]);   // gasPrice=20e9
    inner.extend([0x82, 0x52, 0x08]);                     // gasLimit=21000
    inner.push(0x94);                                     // to: 20-byte string
    inner.extend(to_bytes);
    inner.extend(value_item);                             // value=amount
    inner.push(0x80);                                     // data=""

    let len = inner.len();
    let mut rlp = vec![];
    if len <= 55 {
        rlp.push(0xc0 + len as u8);
    } else {
        let mut lb = vec![];
        let mut l = len;
        while l > 0 {
            lb.push((l & 0xff) as u8);
            l >>= 8;
        }
        lb.reverse();
        rlp.push(0xf7 + lb.len() as u8);
        rlp.extend(lb);
    }
    rlp.extend(inner);
    rlp
}

/// policy with signer bob + vendor allowlist — the standard demo setup
fn setup_demo_policy(c: &mut Contract, id: &str, max_tx: u128, daily: u128) {
    make_policy(c, id, max_tx, daily);
    c.set_signer(id.into(), bob());
    c.set_allowed_recipients(id.into(), vec![VENDOR.into()]);
}

/// request_signature that passes policy returns a Promise; one that
/// fails panics. helper to assert the promise branch without tripping
/// the deny paths.
fn expect_allow(c: &mut Contract, id: &str, payload: Vec<u8>) {
    let r = c.request_signature(
        id.into(),
        "eth/0".into(),
        "ecdsa".into(),
        payload,
    );
    assert!(
        matches!(r, PromiseOrValue::Promise(_)),
        "expected policy to allow"
    );
}

#[allow(dead_code)]
fn expect_deny(c: &mut Contract, id: &str, payload: Vec<u8>) -> String {
    // deny paths: (a) revert panic (frozen/tripped/cooldown/rate/auth/rlp)
    //             (b) persist + return (recipient/over_tx/over_daily — trip persists)
    use std::panic;
    let prev = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let r = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        c.request_signature(id.into(), "eth/0".into(), "ecdsa".into(), payload)
    }));
    panic::set_hook(prev);
    match r {
        Err(e) => {
            let s = if let Some(msg) = e.downcast_ref::<String>() { msg.clone() }
                    else if let Some(w) = e.downcast_ref::<&str>() { w.to_string() }
                    else { format!("{:?}", e) };
            if let Some(start) = s.find("panic_msg: ") {
                let rest = &s[start + 11..];
                let msg = rest.split('\\').next().unwrap_or(&s);
                let m = msg.trim_matches('"');
                let end = m.find('"').unwrap_or(m.len());
                m[..end].to_string()
            } else { s }
        }
        Ok(PromiseOrValue::Value(reason)) => {
            // persist-deny: trip must persist, reason is in the returned string
            let p = c.policies.get(&id.to_string()).cloned().unwrap();
            assert!(p.tripped, "persist-deny expected tripped pin");
            reason.split(':').next().unwrap_or(&reason).to_string()
        }
        Ok(PromiseOrValue::Promise(_)) => panic!("expected deny, got allow (promise issued)"),
    }
}

#[test]
fn create_and_read_policy() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500);
    let v = c.get_policy("p1".into()).unwrap();
    assert_eq!(v.max_tx, 100);
    assert_eq!(v.daily_limit, 500);
    assert_eq!(v.status, "ok");
    assert_eq!(c.policy_len(), 1);
    // fresh policy denies all recipients (fail-closed default)
    assert!(v.allowed_recipients.is_empty());
}

#[test]
#[should_panic(expected = "policy exists")]
fn duplicate_policy_rejected() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500);
    make_policy(&mut c, "p1", 100, 500);
}

#[test]
#[should_panic(expected = "daily_limit < max_tx")]
fn daily_below_tx_rejected() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 500, 100);
}

#[test]
#[should_panic(expected = "SHEARPIN_NO_POLICY")]
fn missing_policy_fails_closed() {
    testing_env!(base_ctx());
    let mut c = fresh();
    c.request_signature(
        "ghost".into(),
        "eth/0".into(),
        "ecdsa".into(),
        make_rlp_tx(1),
    );
}

#[test]
#[should_panic(expected = "SHEARPIN_SIGNER")]
fn stranger_cannot_request() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    let charlie: AccountId = "charlie.near".parse().unwrap();
    let mut ctx = base_ctx();
    ctx.predecessor_account_id = charlie;
    testing_env!(ctx);
    c.request_signature(
        "p1".into(),
        "eth/0".into(),
        "ecdsa".into(),
        make_rlp_tx(10),
    );
}

#[test]
fn signer_can_request_after_registration() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    let mut ctx = base_ctx();
    ctx.predecessor_account_id = bob();
    testing_env!(ctx);
    expect_allow(&mut c, "p1", make_rlp_tx(10));
}

#[test]
fn over_tx_cap_snaps_pin() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    let mut ctx = base_ctx();
    ctx.predecessor_account_id = bob();
    testing_env!(ctx);
    // amount comes from the RLP value field: 101 > max_tx 100
    assert_eq!(expect_deny(&mut c, "p1", make_rlp_tx(101)), "SHEARPIN_OVER_TX");
    assert_eq!(c.policy_status("p1".into()), "tripped");
}

#[test]
fn pin_trips_on_over_tx_and_blocks_next() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    let mut p = c.policies.get(&"p1".to_string()).cloned().unwrap();
    p.tripped = true;
    c.policies.insert("p1".to_string(), p.clone());
    assert_eq!(c.policy_status("p1".into()), "tripped");
    let restored = c.reset_pin("p1".into());
    assert!(!restored.tripped);
}

#[test]
fn tripped_pin_denies_requests() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    let mut p = c.policies.get(&"p1".to_string()).cloned().unwrap();
    p.tripped = true;
    c.policies.insert("p1".to_string(), p.clone());
    let mut ctx = base_ctx(); ctx.block_index += 10_000; ctx.predecessor_account_id = bob(); testing_env!(ctx);
    assert_eq!(expect_deny(&mut c, "p1", make_rlp_tx(1)), "SHEARPIN_TRIPPED");
}

#[test]
fn over_daily_cap_snaps_pin() {
    testing_env!(base_ctx());
    let mut c = fresh();
    // rate limit high (10) so the DAILY cap trips, not the rate cap
    setup_demo_policy_rate(&mut c, "p1", 100, 500, 10);
    for i in 0..5 {
        let mut ctx = base_ctx(); ctx.block_index += 100 * (i + 1); ctx.predecessor_account_id = bob(); testing_env!(ctx);
        expect_allow(&mut c, "p1", make_rlp_tx(100));
    }
    let mut ctx = base_ctx(); ctx.block_index += 700; ctx.predecessor_account_id = bob(); testing_env!(ctx);
    assert_eq!(expect_deny(&mut c, "p1", make_rlp_tx(1)), "SHEARPIN_OVER_DAILY");
    assert_eq!(c.policy_status("p1".into()), "tripped");
}

/// like setup_demo_policy but with a custom rate limit
fn setup_demo_policy_rate(c: &mut Contract, id: &str, max_tx: u128, daily: u128, rate: u32) {
    c.create_policy(id.into(), "sat-1".into(), U128(max_tx), U128(daily), 10, rate);
    c.set_signer(id.into(), bob());
    c.set_allowed_recipients(id.into(), vec![VENDOR.into()]);
}

#[test]
fn cooldown_blocks_rapid_fire() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    let mut ctx = base_ctx(); ctx.predecessor_account_id = bob(); testing_env!(ctx);
    expect_allow(&mut c, "p1", make_rlp_tx(10));
    assert_eq!(expect_deny(&mut c, "p1", make_rlp_tx(10)), "SHEARPIN_COOLDOWN");
}

#[test]
fn rate_cap_trips() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 10_000);
    for i in 0..5 {
        let mut ctx = base_ctx(); ctx.block_index += 100 * (i + 1); ctx.predecessor_account_id = bob(); testing_env!(ctx);
        expect_allow(&mut c, "p1", make_rlp_tx(10));
    }
    let mut ctx = base_ctx(); ctx.block_index += 700; ctx.predecessor_account_id = bob(); testing_env!(ctx);
    assert_eq!(expect_deny(&mut c, "p1", make_rlp_tx(10)), "SHEARPIN_RATE");
}

#[test]
fn freeze_blocks_everything() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    c.freeze("p1".into());
    let mut ctx = base_ctx(); ctx.block_index += 100; ctx.predecessor_account_id = bob(); testing_env!(ctx);
    assert_eq!(expect_deny(&mut c, "p1", make_rlp_tx(1)), "SHEARPIN_FROZEN");
}

#[test]
fn unfreeze_restores() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    c.freeze("p1".into());
    assert_eq!(c.policy_status("p1".into()), "frozen");
    c.unfreeze("p1".into());
    assert_eq!(c.policy_status("p1".into()), "ok");
}

#[test]
#[should_panic(expected = "SHEARPIN_OWNER")]
fn only_owner_can_freeze() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    let mut ctx = base_ctx();
    ctx.predecessor_account_id = bob();
    testing_env!(ctx);
    c.freeze("p1".into());
}

#[test]
#[should_panic(expected = "SHEARPIN_OWNER")]
fn only_owner_can_update() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    let mut ctx = base_ctx();
    ctx.predecessor_account_id = bob();
    testing_env!(ctx);
    c.update_policy("p1".into(), Some(U128(999)), None, None, None);
}

#[test]
fn day_rollover_resets_counters() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    let mut ctx = base_ctx(); ctx.predecessor_account_id = bob(); testing_env!(ctx);
    expect_allow(&mut c, "p1", make_rlp_tx(100));
    let v = c.get_policy("p1".into()).unwrap();
    assert_eq!(v.spent_today, 100);

    let mut ctx = base_ctx();
    ctx.block_index += BLOCKS_PER_DAY + 100;
    ctx.predecessor_account_id = bob();
    testing_env!(ctx);
    expect_allow(&mut c, "p1", make_rlp_tx(50));
    let v = c.get_policy("p1".into()).unwrap();
    assert_eq!(v.spent_today, 50, "day rollover must reset spent_today");
    assert_eq!(v.requests_today, 1);
}

#[test]
fn update_policy_changes_limits() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    let v = c.update_policy("p1".into(), Some(U128(200)), Some(U128(1000)), None, None);
    assert_eq!(v.max_tx, 200);
    assert_eq!(v.daily_limit, 1000);
}

#[test]
fn init_is_fresh_per_env() {
    testing_env!(base_ctx());
    let c = fresh();
    assert_eq!(c.policy_len(), 0);
}

#[test]
#[should_panic(expected = "SHEARPIN_KEY_TYPE")]
fn unknown_key_type_rejected() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    let mut ctx = base_ctx(); ctx.predecessor_account_id = bob(); testing_env!(ctx);
    c.request_signature(
        "p1".into(),
        "eth/0".into(),
        "qr".into(),
        make_rlp_tx(10),
    );
}

// ============ security-fix tests: RLP-derived amounts + allowlist ============

#[test]
fn empty_allowlist_denies_all() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500); // no set_allowed_recipients
    c.set_signer("p1".into(), bob());
    let mut ctx = base_ctx(); ctx.predecessor_account_id = bob(); testing_env!(ctx);
    assert_eq!(expect_deny(&mut c, "p1", make_rlp_tx(10)), "SHEARPIN_RECIPIENT");
    assert_eq!(c.policy_status("p1".into()), "tripped", "allowlist deny must snap the pin");
}

#[test]
fn recipient_not_in_allowlist_denied() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    let mut ctx = base_ctx(); ctx.predecessor_account_id = bob(); testing_env!(ctx);
    // attacker address not in the allowlist
    let attacker = "0x0000000000000000000000000000000000000001";
    assert_eq!(expect_deny(&mut c, "p1", make_rlp_tx_to_addr(attacker, 10)), "SHEARPIN_RECIPIENT");
}

#[test]
fn amount_comes_from_rlp_not_caller() {
    // the core security property: caller supplies NO amount. the value
    // checked against the caps is parsed from the RLP payload. a tx whose
    // value field is 101 must trip even though the caller "said" nothing.
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    let mut ctx = base_ctx(); ctx.predecessor_account_id = bob(); testing_env!(ctx);
    let payload = make_rlp_tx(101); // value baked into the RLP
    assert_eq!(expect_deny(&mut c, "p1", payload), "SHEARPIN_OVER_TX");
}

#[test]
fn rlp_parse_extracts_correct_amount_and_recipient() {
    let tx = parse_unsigned_legacy_tx(&make_rlp_tx(12345)).unwrap();
    assert_eq!(tx.value, 12345);
    assert_eq!(tx.to, VENDOR);
}

#[test]
#[should_panic(expected = "SHEARPIN_RLP_ERROR")]
fn malformed_rlp_fails_closed() {
    testing_env!(base_ctx());
    let mut c = fresh();
    setup_demo_policy(&mut c, "p1", 100, 500);
    let mut ctx = base_ctx(); ctx.predecessor_account_id = bob(); testing_env!(ctx);
    c.request_signature(
        "p1".into(),
        "eth/0".into(),
        "ecdsa".into(),
        vec![0x00], // not valid RLP
    );
}

#[test]
fn set_allowed_recipients_normalizes_and_dedupes() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500);
    let v = c.set_allowed_recipients("p1".into(), vec![
        "D4E56740F876AFEC8011E179A8B763074E6B5C8F".into(), // uppercase, no 0x
        "0xD4E56740F876AFEC8011E179A8B763074E6B5C8F".into(), // duplicate after normalize
        "0x1111111111111111111111111111111111111111".into(),
    ]);
    assert_eq!(v.allowed_recipients.len(), 2);
    assert!(v.allowed_recipients.contains(&VENDOR.to_string()));
    assert!(v.allowed_recipients.contains(&"0x1111111111111111111111111111111111111111".to_string()));
}

#[test]
#[should_panic(expected = "too many recipients")]
fn too_many_recipients_rejected() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500);
    let many: Vec<String> = (0..33).map(|i| format!("0x{:040x}", i)).collect();
    c.set_allowed_recipients("p1".into(), many);
}

#[test]
fn deny_log_includes_recipient() {
    // exercised through lib::deny — format check
    let log = deny("p1", "test_reason", 42, "0xabcdef");
    assert!(log.contains("\"recipient\":\"0xabcdef\""));
    assert!(log.contains("\"amount\":42"));
}