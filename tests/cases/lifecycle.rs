use crate::support::*;
use cgrp::*;
use std::collections::BTreeSet;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn privacy_forks_timeout_and_shrink() {
    let s = circle(12);
    let p = policy();
    assert_eq!(
        view(&s, &[1; 32], &p, 0).unwrap().next,
        NextChange::ConsentIngroup
    );
    let s = ingroup(42);
    assert_eq!(s.members(&[1; 32]).unwrap().len(), 12);
    assert_eq!(view(&s, &[2; 32], &p, 0).unwrap().level, Level::Ingroup);
    let s = room(42, false);
    assert_eq!(view(&s, &[3; 32], &p, 0).unwrap().level, Level::Opening);
    let r = request(&s, Command::Tick, "m0", BTreeSet::new(), false, 21 * DAY);
    let (s, effects) = apply(&s, &r, 21 * DAY);
    assert!(
        effects
            .iter()
            .any(|e| e.event() == &Effect::ConsentLapsed { group: [3; 32] })
    );
    assert_eq!(
        view(&s, &[3; 32], &p, 21 * DAY).unwrap().level,
        Level::Ingroup
    );
    let mut s = room(43, false);
    assert_eq!(
        view(&s, &[3; 32], &p, 3 * DAY).unwrap().level,
        Level::Public
    );
    for i in (10..43).rev() {
        let r = request(
            &s,
            Command::Leave { group: [3; 32] },
            &format!("m{i}"),
            members(i, i + 1),
            false,
            3 * DAY,
        );
        s = apply(&s, &r, 3 * DAY).0;
        let v = view(&s, &[3; 32], &p, 3 * DAY).unwrap();
        assert_eq!(
            v.level,
            if i > 36 {
                Level::Public
            } else if i > 10 {
                Level::Ingroup
            } else {
                Level::Circle
            }
        );
    }
    let s = room(3, true);
    let r = request(&s, Command::Tick, "m0", BTreeSet::new(), false, 22 * DAY);
    let s = apply(&s, &r, 22 * DAY).0;
    assert_eq!(
        view(&s, &[3; 32], &p, 22 * DAY).unwrap().next,
        NextChange::Seed
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn consent_and_atomic_publication_refuse_replay_and_corruption() {
    let s = Snapshot::empty("test-community".into());
    let good = request(
        &s,
        Command::Create {
            id: [1; 32],
            members: members(0, 3),
            seed: false,
        },
        "m0",
        members(0, 3),
        false,
        0,
    );
    let p = SignedPolicy::new(&policy());
    for index in 0..3 {
        let mut bad = good.clone();
        bad.consents[index].signature[0] ^= 1;
        assert!(matches!(
            prepare(&s, &bad, &p, &TestAuthority, 0, 128),
            Err(Error::Authority)
        ));
    }
    let mut bad = good.clone();
    bad.consents.pop();
    assert!(matches!(
        prepare(&s, &bad, &p, &TestAuthority, 0, 128),
        Err(Error::Authority)
    ));
    let mut corrupted = SignedPolicy::new(&policy());
    corrupted.corrupt();
    assert!(matches!(
        prepare(&s, &good, &corrupted, &TestAuthority, 0, 128),
        Err(Error::Authority)
    ));
    for outcome in [Commit::Conflict, Commit::Unknown] {
        let mut store = Store::new(&s);
        store.outcome = outcome;
        let result = futures::executor::block_on(
            prepare(&s, &good, &p, &TestAuthority, 0, 128)
                .unwrap()
                .persist(&mut store),
        );
        assert_eq!(
            result.unwrap_err(),
            if outcome == Commit::Conflict {
                Error::Conflict
            } else {
                Error::Reconcile
            }
        );
    }
    let (next, effects) = apply(&s, &good, 0);
    assert_eq!(effects.len(), 1);
    assert!(matches!(
        prepare(&next, &good, &p, &TestAuthority, 0, 128),
        Err(Error::Conflict)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn exit_forks_preserve_nonmovers_and_cooldowns() {
    let s = circle(6);
    let r = request(
        &s,
        Command::Fork {
            id: [4; 32],
            parents: vec![[1; 32]],
            members: members(0, 5),
            kind: ForkKind::Exclusion {
                target: "m5".into(),
            },
        },
        "m0",
        members(0, 5),
        false,
        0,
    );
    let s = apply(&s, &r, 0).0;
    assert!(s.members(&[1; 32]).unwrap().contains("m5"));
    assert!(!s.members(&[4; 32]).unwrap().contains("m5"));
    let r = request(
        &s,
        Command::Fork {
            id: [5; 32],
            parents: vec![[1; 32]],
            members: members(0, 5),
            kind: ForkKind::Exclusion {
                target: "m5".into(),
            },
        },
        "m0",
        members(0, 5),
        false,
        15 * DAY,
    );
    assert!(matches!(
        prepare(
            &s,
            &r,
            &SignedPolicy::new(&policy()),
            &TestAuthority,
            15 * DAY,
            128
        ),
        Err(Error::Conflict)
    ));
    let r = request(
        &s,
        Command::Fork {
            id: [5; 32],
            parents: vec![[1; 32]],
            members: members(0, 4),
            kind: ForkKind::Split,
        },
        "m0",
        members(0, 4),
        false,
        28 * DAY,
    );
    let s = apply(&s, &r, 28 * DAY).0;
    let r = request(
        &s,
        Command::Fork {
            id: [6; 32],
            parents: vec![[4; 32], [5; 32]],
            members: members(0, 5),
            kind: ForkKind::Merge,
        },
        "m0",
        members(0, 5),
        false,
        28 * DAY,
    );
    let s = apply(&s, &r, 28 * DAY).0;
    assert_eq!(
        view(&s, &[6; 32], &policy(), 28 * DAY).unwrap().lineage,
        [1; 32]
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn cap_and_room_join_pacing() {
    let mut s = room(80, true);
    for i in 80..86 {
        let r = request(
            &s,
            Command::Join {
                group: [3; 32],
                member: format!("m{i}"),
                vouches: BTreeSet::new(),
            },
            &format!("m{i}"),
            members(i, i + 1),
            true,
            0,
        );
        s = apply(&s, &r, 0).0;
    }
    let r = request(
        &s,
        Command::Join {
            group: [3; 32],
            member: "m86".into(),
            vouches: BTreeSet::new(),
        },
        "m86",
        members(86, 87),
        true,
        0,
    );
    assert!(matches!(
        prepare(
            &s,
            &r,
            &SignedPolicy::new(&policy()),
            &TestAuthority,
            0,
            128
        ),
        Err(Error::Capacity)
    ));
    let s = room(100, true);
    let r = request(
        &s,
        Command::Join {
            group: [3; 32],
            member: "m100".into(),
            vouches: BTreeSet::new(),
        },
        "m100",
        members(100, 101),
        true,
        0,
    );
    assert!(matches!(
        prepare(
            &s,
            &r,
            &SignedPolicy::new(&policy()),
            &TestAuthority,
            0,
            128
        ),
        Err(Error::Capacity)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn inherited_opening_forks_preserve_deadline_and_visibility() {
    for (kind, movers) in [
        (
            ForkKind::Add,
            members(0, 41).into_iter().chain(["m50".into()]).collect(),
        ),
        (ForkKind::Split, members(0, 30)),
        (
            ForkKind::Exclusion {
                target: "m41".into(),
            },
            members(0, 41),
        ),
    ] {
        let s = room(42, false);
        let command = Command::Fork {
            id: [4; 32],
            parents: vec![[3; 32]],
            members: movers.clone(),
            kind,
        };
        let refused = request(&s, command.clone(), "m0", movers.clone(), false, 5 * DAY);
        assert!(matches!(
            prepare(
                &s,
                &refused,
                &SignedPolicy::new(&policy()),
                &TestAuthority,
                5 * DAY,
                128
            ),
            Err(Error::Authority)
        ));
        let signed = request(&s, command, "m0", movers, true, 5 * DAY);
        let (s, _) = apply(&s, &signed, 5 * DAY);
        assert_eq!(
            view(&s, &[4; 32], &policy(), 5 * DAY).unwrap().next,
            NextChange::OpeningDeadline(21 * DAY)
        );
        assert_eq!(
            view(&s, &[3; 32], &policy(), 5 * DAY).unwrap().next,
            NextChange::OpeningDeadline(21 * DAY)
        );
        let tick = request(
            &s,
            Command::Tick,
            "m0",
            BTreeSet::new(),
            false,
            21 * DAY - 1,
        );
        let (s, _) = apply(&s, &tick, 21 * DAY - 1);
        assert_eq!(
            view(&s, &[4; 32], &policy(), 21 * DAY - 1).unwrap().level,
            Level::Opening
        );
        let tick = request(&s, Command::Tick, "m0", BTreeSet::new(), false, 21 * DAY);
        let (s, effects) = apply(&s, &tick, 21 * DAY);
        assert_eq!(
            view(&s, &[4; 32], &policy(), 21 * DAY).unwrap().level,
            Level::Ingroup
        );
        assert!(
            effects
                .iter()
                .any(|e| e.event() == &Effect::ConsentLapsed { group: [4; 32] })
        );
    }
}
