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
    let s = room(42);
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
    let mut s = room(43);
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
                .persist(&mut store, 0),
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
    // After the last join the room's rooms were built with.
    const LATER: u64 = 200 * 3_600;
    let mut s = room(80);
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
            LATER,
        );
        s = apply(&s, &r, LATER).0;
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
        LATER,
    );
    assert!(matches!(
        prepare(
            &s,
            &r,
            &SignedPolicy::new(&policy()),
            &TestAuthority,
            LATER,
            128
        ),
        Err(Error::Capacity)
    ));
    let s = room(100);
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
        LATER,
    );
    assert!(matches!(
        prepare(
            &s,
            &r,
            &SignedPolicy::new(&policy()),
            &TestAuthority,
            LATER,
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
        let s = room(42);
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn pending_work_cannot_outlive_signed_consent() {
    let s = Snapshot::empty("test-community".into());
    let r = request(
        &s,
        Command::Create {
            id: [1; 32],
            members: members(0, 3),
        },
        "m0",
        members(0, 3),
        false,
        5,
    );
    for (now, error) in [(4, Error::Clock), (5 + DAY, Error::Authority)] {
        let candidate = prepare(
            &s,
            &r,
            &SignedPolicy::new(&policy()),
            &TestAuthority,
            5,
            128,
        )
        .unwrap();
        assert_eq!(candidate.prepare_effects()[0].valid_until(), 5 + DAY);
        let mut store = Store::new(&s);
        assert_eq!(
            futures::executor::block_on(candidate.persist(&mut store, now)).unwrap_err(),
            error
        );
        assert_eq!(store.revision, 0);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn read_only_membership_interface_lists_groups_and_views() {
    let s = ingroup(42);
    let p = policy();
    let ids: Vec<Id> = s.ids().copied().collect();
    assert!(ids.contains(&[2; 32]));
    let views = s.views(&p, 0).unwrap();
    assert_eq!(views.len(), ids.len());
    for (id, v) in ids.iter().zip(&views) {
        assert_eq!(&v.id, id);
        assert_eq!(v, &view(&s, id, &p, 0).unwrap());
        assert_eq!(usize::from(v.size), s.members(id).unwrap().len());
    }
    let mut stale = policy();
    stale.valid_until = 0;
    assert_eq!(s.views(&stale, 0), Err(Error::Policy));
    assert_eq!(Snapshot::empty("c".into()).views(&p, 0).unwrap(), vec![]);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn growth_thresholds_are_settings_within_bounds() {
    let mut small = policy();
    small.circle_max = 3;
    small.ingroup_max = 5;
    small.shrink_public = 4;
    small.shrink_ingroup = 2;
    small.split_public_min = 6;
    assert!(small.validate(0).is_ok());
    let mut bad = small.clone();
    bad.circle_max = 2;
    assert!(bad.validate(0).is_err());
    let mut bad = small.clone();
    bad.ingroup_max = 43;
    assert!(bad.validate(0).is_err());
    let mut bad = small.clone();
    bad.shrink_public = 3;
    assert!(bad.validate(0).is_err());
    let mut bad = small;
    bad.cap = 257;
    assert!(bad.validate(0).is_err());
}
