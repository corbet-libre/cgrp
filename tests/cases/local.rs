use crate::support::*;
use cgrp::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn all_bands_history_and_weight() {
    let mut p = policy();
    p.validate(0).unwrap();
    for i in 0..9 {
        assert_eq!(p.band(p.bands[i].enter_up, 0).unwrap(), i);
        assert_eq!(p.band(p.bands[i].enter_up, i).unwrap(), i);
    }
    assert_eq!(p.band(18, 4).unwrap(), 3);
    p.bands[4].enter_up = 22;
    assert_eq!(p.band(20, 3).unwrap(), 3);
    assert_eq!(p.band(22, 3).unwrap(), 4);
    assert!((p.seat_weight(3) - 1.21).abs() < 1e-10);
    assert_eq!(p.seat_weight(60), 0.25);
    assert_eq!(p.seat_weight(100), 3.25);
    assert!(!history_allowed(20 * DAY, 19 * DAY, &p.bands[0]));
    assert!(history_allowed(20 * DAY, 19 * DAY, &p.bands[6]));
    assert!(!history_allowed(20 * DAY, 18 * DAY, &p.bands[6]));
    assert!(!history_allowed(20 * DAY, 21 * DAY, &p.bands[6]));
    p.seats.enabled = true;
    assert_eq!(p.validate(0), Err(Error::Policy));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn device_activity_and_local_suggestions() {
    let mut a = ActivityLedger::default();
    for _ in 0..6 {
        a.record(Activity::Message, 0, 100).unwrap();
        a.record(Activity::Reaction, 0, 100).unwrap();
    }
    a.record(Activity::Welcome { receipt: [1; 32] }, 0, 100)
        .unwrap();
    a.record(Activity::Introduction { receipt: [2; 32] }, 0, 100)
        .unwrap();
    assert_eq!(a.points_tenths(0).unwrap(), 82);
    assert_eq!(a.points_tenths(7 * DAY).unwrap(), 0);
    a.record(Activity::Message, 7 * DAY, 100).unwrap();
    assert_eq!(a.points_tenths(7 * DAY).unwrap(), 10);
    assert_eq!(a.record(Activity::Message, 0, 100), Err(Error::Clock));
    let p = policy();
    let edges = vec![
        ("m0".into(), "m1".into(), 4),
        ("m34".into(), "m35".into(), 4),
    ];
    assert!(matches!(
        fission(&members(0, 66), &members(0, 33), &edges, &p).unwrap(),
        Some(Suggestion::Fission { .. })
    ));
    assert_eq!(
        fission(&members(0, 85), &members(0, 42), &[], &p).unwrap(),
        Some(Suggestion::Crowded)
    );
    assert!(fusion("m0", &members(0, 6), &members(0, 8), [1; 32], &p).is_some());
    let mut ledger = SuggestionLedger::default();
    assert!(ledger.available(&[1; 32], 0, &p).unwrap());
    ledger.shown([1; 32], 0);
    assert!(!ledger.available(&[1; 32], DAY, &p).unwrap());
    assert!(ledger.available(&[1; 32], 7 * DAY, &p).unwrap());
    ledger.declined([1; 32], 7 * DAY);
    assert!(!ledger.available(&[1; 32], 20 * DAY, &p).unwrap());
    assert!(ledger.available(&[1; 32], 21 * DAY, &p).unwrap());
    ledger.prune(21 * DAY);
}

struct UnavailableAccounting;
impl Accounting for UnavailableAccounting {
    type Acceptance = ();
    fn grant(&mut self, _: &ReceiptRequest, _: &[Vec<u8>], _: &Policy) -> Result<()> {
        Err(Error::Unavailable)
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn receipt_preparation_never_forges_an_accounting_grant() {
    let p = policy();
    let welcome = ReceiptRequest::welcome(
        ReceiptContext {
            operation: [1; 32],
            community: "test-community".into(),
            group: [2; 32],
            beneficiary: "m0".into(),
        },
        "m1".into(),
        0,
        DAY,
        &p,
    )
    .unwrap();
    let introduction = ReceiptRequest::introduction(
        ReceiptContext {
            operation: [3; 32],
            community: "test-community".into(),
            group: [2; 32],
            beneficiary: "m0".into(),
        },
        members(1, 3),
        0,
        [DAY, 2 * DAY],
        &p,
    )
    .unwrap();
    assert_ne!(
        welcome.signing_bytes().unwrap(),
        introduction.signing_bytes().unwrap()
    );
    assert_eq!(
        request_credit(&mut UnavailableAccounting, &welcome, &[vec![1]], &p, DAY),
        Err(Error::Unavailable)
    );
    assert_eq!(
        request_credit(
            &mut UnavailableAccounting,
            &introduction,
            &[vec![1], vec![2]],
            &p,
            2 * DAY
        ),
        Err(Error::Unavailable)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn local_bounds_reject_invalid_activity_graphs_and_receipts() {
    let p = policy();
    let mut a = ActivityLedger::default();
    assert_eq!(
        a.record(Activity::Welcome { receipt: [1; 32] }, 0, 0),
        Err(Error::Capacity)
    );
    a.record(Activity::Introduction { receipt: [1; 32] }, DAY, 2)
        .unwrap();
    a.record(Activity::Introduction { receipt: [2; 32] }, DAY, 2)
        .unwrap();
    assert_eq!(
        a.record(Activity::Introduction { receipt: [3; 32] }, DAY, 2),
        Err(Error::Capacity)
    );
    assert_eq!(a.points_tenths(0), Err(Error::Clock));
    let roster = members(0, 66);
    let left = members(0, 33);
    assert_eq!(
        fission(&roster, &members(0, 0), &[], &p),
        Err(Error::Invalid)
    );
    assert_eq!(fission(&roster, &roster, &[], &p), Err(Error::Invalid));
    assert_eq!(
        fission(&roster, &members(67, 68), &[], &p),
        Err(Error::Invalid)
    );
    assert_eq!(
        fission(&members(0, 12), &members(0, 6), &[], &p).unwrap(),
        None
    );
    assert_eq!(fission(&roster, &left, &[], &p).unwrap(), None);
    assert_eq!(
        fission(&roster, &left, &[("m0".into(), "m33".into(), 1)], &p).unwrap(),
        None
    );
    for (x, y) in [("m0", "m0"), ("m90", "m0"), ("m0", "m90")] {
        assert_eq!(
            fission(&roster, &left, &[(x.into(), y.into(), 1)], &p),
            Err(Error::Invalid)
        );
    }
    assert!(fusion("m90", &members(0, 6), &members(0, 8), [1; 32], &p).is_none());
    assert!(fusion("m0", &members(0, 6), &members(1, 8), [1; 32], &p).is_none());
    assert!(fusion("m0", &members(0, 6), &members(0, 14), [1; 32], &p).is_none());
    assert!(fusion("m5", &members(0, 6), &members(5, 12), [1; 32], &p).is_none());
    let mut ledger = SuggestionLedger::default();
    ledger.shown([1; 32], 10);
    assert_eq!(ledger.available(&[1; 32], 9, &p), Err(Error::Clock));
    ledger.declined([2; 32], 10);
    assert_eq!(ledger.available(&[2; 32], 9, &p), Err(Error::Clock));
    ledger.prune(0);
    assert!(!ledger.available(&[1; 32], 10, &p).unwrap());
    let context = || ReceiptContext {
        operation: [1; 32],
        community: "test-community".into(),
        group: [1; 32],
        beneficiary: "m0".into(),
    };
    for (join, reply, newcomer) in [(DAY, 0, "m1"), (0, 4 * DAY, "m1"), (0, DAY, "m0")] {
        assert_eq!(
            ReceiptRequest::welcome(context(), newcomer.into(), join, reply, &p),
            Err(Error::Invalid)
        );
    }
    for (peers, start, answers) in [
        (members(1, 2), 0, [0, 0]),
        (members(0, 2), 0, [0, 0]),
        (members(1, 3), DAY, [0, DAY]),
        (members(1, 3), 0, [0, 15 * DAY]),
    ] {
        assert_eq!(
            ReceiptRequest::introduction(context(), peers, start, answers, &p),
            Err(Error::Invalid)
        );
    }
    let r = ReceiptRequest::welcome(context(), "m1".into(), 0, DAY, &p).unwrap();
    let mut off = p.clone();
    off.reciprocity_enabled = false;
    assert_eq!(
        request_credit(&mut UnavailableAccounting, &r, &[vec![]], &off, DAY),
        Err(Error::Authority)
    );
    let mut next = p.clone();
    next.epoch = 2;
    assert_eq!(
        request_credit(&mut UnavailableAccounting, &r, &[vec![]], &next, DAY),
        Err(Error::Authority)
    );
    assert_eq!(
        request_credit(&mut UnavailableAccounting, &r, &[vec![]], &p, 0),
        Err(Error::Authority)
    );
    assert_eq!(
        request_credit(&mut UnavailableAccounting, &r, &[vec![]], &p, 4 * DAY),
        Err(Error::Authority)
    );
    assert_eq!(
        request_credit(&mut UnavailableAccounting, &r, &[], &p, DAY),
        Err(Error::Authority)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn receipt_replay_cannot_inflate_next_days_activity() {
    for event in [
        Activity::Welcome { receipt: [1; 32] },
        Activity::Introduction { receipt: [2; 32] },
    ] {
        let mut ledger = ActivityLedger::default();
        ledger.record(event, 0, 100).unwrap();
        assert_eq!(ledger.record(event, DAY, 100), Err(Error::Conflict));
    }
}
