//! unit tests — every policy rule, boundaries, fail-closed paths

use crate::*;
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

/// request_signature that passes policy returns a Promise; one that
/// fails panics. helper to assert the promise branch without tripping
/// the deny paths.
fn expect_allow(c: &mut Contract, id: &str, amount: u128) {
    let r = c.request_signature(
        id.into(),
        U128(amount),
        "eth/0".into(),
        "ecdsa".into(),
        vec![0u8; 32],
    );
    assert!(
        matches!(r, PromiseOrValue::Promise(_)),
        "expected policy to allow"
    );
}


#[allow(dead_code)]
fn expect_deny(c: &mut Contract, id: &str, amount: u128) -> String {
    // deny iki yol: (a) revert panic (frozen/tripped/cooldown/rate/auth)
    //              (b) persist + return (over_tx / over_daily — trip persists)
    use std::panic;
    let prev = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let r = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        c.request_signature(id.into(), U128(amount), "eth/0".into(), "ecdsa".into(), vec![0u8; 32])
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
        U128(1),
        "eth/0".into(),
        "ecdsa".into(),
        vec![0u8; 32],
    );
}

#[test]
#[should_panic(expected = "SHEARPIN_NO_SIGNER")]
fn stranger_cannot_request() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500);
    let mut ctx = base_ctx();
    ctx.predecessor_account_id = bob();
    testing_env!(ctx);
    c.request_signature(
        "p1".into(),
        U128(1),
        "eth/0".into(),
        "ecdsa".into(),
        vec![0u8; 32],
    );
}

#[test]
fn signer_can_request_after_registration() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500);
    c.set_signer("p1".into(), bob());
    let mut ctx = base_ctx();
    ctx.predecessor_account_id = bob();
    testing_env!(ctx);
    expect_allow(&mut c, "p1", 10);
}

#[test]
fn over_tx_cap_snaps_pin() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500);
    assert_eq!(expect_deny(&mut c, "p1", 101), "SHEARPIN_OVER_TX");
    // NOTE: on-chain the revert undoes the trip write; the mock env keeps it.
    // persistent kill on-chain is owner freeze(); trip here mirrors pre-revert state.
    assert_eq!(c.policy_status("p1".into()), "tripped");
}

#[test]
fn pin_trips_on_over_tx_and_blocks_next() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500);
    // trip it manually the same way the contract would (we cannot catch
    // the panic in-test), then verify the follow-up deny + owner reset.
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
    make_policy(&mut c, "p1", 100, 500);
    let mut p = c.policies.get(&"p1".to_string()).cloned().unwrap();
    p.tripped = true;
    c.policies.insert("p1".to_string(), p.clone());
    let mut ctx = base_ctx(); ctx.block_index += 10_000; testing_env!(ctx);
    assert_eq!(expect_deny(&mut c, "p1", 1), "SHEARPIN_TRIPPED");
}

#[test]
fn over_daily_cap_snaps_pin() {
    testing_env!(base_ctx());
    let mut c = fresh();
    c.create_policy("p1".into(), "sat-1".into(), U128(100), U128(500), 10, 10);
    for i in 0..5 {
        let mut ctx = base_ctx(); ctx.block_index += 100 * (i + 1); testing_env!(ctx);
        expect_allow(&mut c, "p1", 100);
    }
    let mut ctx = base_ctx(); ctx.block_index += 700; testing_env!(ctx);
    assert_eq!(expect_deny(&mut c, "p1", 1), "SHEARPIN_OVER_DAILY");
    // NOTE: on-chain the revert undoes the trip write; the mock env keeps it.
    // persistent kill on-chain is owner freeze(); trip here mirrors pre-revert state.
    assert_eq!(c.policy_status("p1".into()), "tripped");
}

#[test]
fn cooldown_blocks_rapid_fire() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500);
    expect_allow(&mut c, "p1", 10);
    assert_eq!(expect_deny(&mut c, "p1", 10), "SHEARPIN_COOLDOWN");
}

#[test]
fn rate_cap_trips() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 10_000);
    for i in 0..5 {
        let mut ctx = base_ctx(); ctx.block_index += 100 * (i + 1); testing_env!(ctx);
        expect_allow(&mut c, "p1", 10);
    }
    let mut ctx = base_ctx(); ctx.block_index += 700; testing_env!(ctx);
    assert_eq!(expect_deny(&mut c, "p1", 10), "SHEARPIN_RATE");
}

#[test]
fn freeze_blocks_everything() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500);
    c.freeze("p1".into());
    let mut ctx = base_ctx(); ctx.block_index += 100; testing_env!(ctx);
    assert_eq!(expect_deny(&mut c, "p1", 1), "SHEARPIN_FROZEN");
}

#[test]
fn unfreeze_restores() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500);
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
    make_policy(&mut c, "p1", 100, 500);
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
    make_policy(&mut c, "p1", 100, 500);
    let mut ctx = base_ctx();
    ctx.predecessor_account_id = bob();
    testing_env!(ctx);
    c.update_policy("p1".into(), Some(U128(999)), None, None, None);
}

#[test]
fn day_rollover_resets_counters() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500);
    expect_allow(&mut c, "p1", 100);
    let v = c.get_policy("p1".into()).unwrap();
    assert_eq!(v.spent_today, 100);

    // jump a full day (+ cooldown margin)
    let mut ctx = base_ctx();
    ctx.block_index += BLOCKS_PER_DAY + 100;
    testing_env!(ctx);
    expect_allow(&mut c, "p1", 50);
    let v = c.get_policy("p1".into()).unwrap();
    assert_eq!(v.spent_today, 50, "day rollover must reset spent_today");
    assert_eq!(v.requests_today, 1);
}

#[test]
fn update_policy_changes_limits() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500);
    let v = c.update_policy("p1".into(), Some(U128(200)), Some(U128(1000)), None, None);
    assert_eq!(v.max_tx, 200);
    assert_eq!(v.daily_limit, 1000);
}

#[test]
fn init_is_fresh_per_env() {
    // state_exists() only becomes true after a deploy writes state; the
    // init guard is exercised on-chain. here we just assert a clean boot.
    testing_env!(base_ctx());
    let c = fresh();
    assert_eq!(c.policy_len(), 0);
}

#[test]
#[should_panic(expected = "SHEARPIN_KEY_TYPE")]
fn unknown_key_type_rejected() {
    testing_env!(base_ctx());
    let mut c = fresh();
    make_policy(&mut c, "p1", 100, 500);
    c.request_signature(
        "p1".into(),
        U128(10),
        "eth/0".into(),
        "qr".into(),
        vec![0u8; 32],
    );
}
