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

/// A test community with small growth thresholds: the ladder circle -> in-group
/// -> public room -> back is walked by the same code and the same rules, only the
/// signed settings differ (no code special case for 12, 42 or 36).
fn small_ladder() -> Policy {
    let mut p = policy();
    p.cap = 20;
    p.circle_max = 4;
    p.ingroup_max = 8;
    p.shrink_public = 6;
    p.shrink_ingroup = 3;
    p.split_public_min = 8;
    p.seats.low = 5;
    p.seats.high = 15;
    p
}

fn apply_with(p: &Policy, state: &Snapshot, r: &Request, now: u64) -> Snapshot {
    let candidate = prepare(state, r, &SignedPolicy::new(p), &TestAuthority, now, 128).unwrap();
    let mut store = Store::new(state);
    futures::executor::block_on(candidate.persist(&mut store, now))
        .unwrap()
        .0
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn growth_thresholds_are_settings_and_a_small_community_walks_the_ladder() {
    let p = small_ladder();
    assert_eq!(p.validate(0), Ok(()));
    // The decided defaults are the ceilings; nothing above them is a setting.
    let mut above = p.clone();
    above.circle_max = 13;
    assert_eq!(above.validate(0), Err(Error::Policy));
    let mut order = p.clone();
    order.shrink_public = order.ingroup_max;
    assert_eq!(order.validate(0), Err(Error::Policy));

    let empty = Snapshot::empty("test-community".into());
    let create = request(
        &empty,
        Command::Create {
            id: [1; 32],
            members: members(0, 4),
        },
        "m0",
        members(0, 4),
        false,
        0,
    );
    let s = apply_with(&p, &empty, &create, 0);
    let v = view(&s, &[1; 32], &p, 0).unwrap();
    assert_eq!(
        (v.level, v.next_at, v.next),
        (Level::Circle, 5, NextChange::ConsentIngroup)
    );
    // More than circle_max members is no circle.
    let too_big = request(
        &empty,
        Command::Create {
            id: [1; 32],
            members: members(0, 5),
        },
        "m0",
        members(0, 5),
        false,
        0,
    );
    assert!(
        prepare(
            &empty,
            &too_big,
            &SignedPolicy::new(&p),
            &TestAuthority,
            0,
            128
        )
        .is_err()
    );

    let add = request(
        &s,
        Command::Fork {
            id: [2; 32],
            parents: vec![[1; 32]],
            members: members(0, 8),
            kind: ForkKind::Add,
        },
        "m0",
        members(0, 8),
        false,
        0,
    );
    let s = apply_with(&p, &s, &add, 0);
    let v = view(&s, &[2; 32], &p, 0).unwrap();
    assert_eq!(
        (v.level, v.next_at, v.next),
        (Level::Ingroup, 9, NextChange::ConsentPublic)
    );

    let open = request(
        &s,
        Command::Fork {
            id: [3; 32],
            parents: vec![[2; 32]],
            members: members(0, 8),
            kind: ForkKind::Open,
        },
        "m0",
        members(0, 8),
        true,
        0,
    );
    let mut s = apply_with(&p, &s, &open, 0);
    assert_eq!(view(&s, &[3; 32], &p, 0).unwrap().level, Level::Opening);
    for i in 8..9 {
        let join = request(
            &s,
            Command::Join {
                group: [3; 32],
                member: format!("m{i}"),
                vouches: BTreeSet::new(),
            },
            &format!("m{i}"),
            members(i, i + 1),
            true,
            i as u64 * 3_600,
        );
        s = apply_with(&p, &s, &join, i as u64 * 3_600);
    }
    let v = view(&s, &[3; 32], &p, 3 * DAY).unwrap();
    assert_eq!(
        (v.level, v.next_at, v.next),
        (Level::Public, 6, NextChange::PrivateIngroup)
    );
    // Shrinking back follows shrink_public, then shrink_ingroup.
    for i in (3..9).rev() {
        let leave = request(
            &s,
            Command::Leave { group: [3; 32] },
            &format!("m{i}"),
            members(i, i + 1),
            false,
            3 * DAY,
        );
        s = apply_with(&p, &s, &leave, 3 * DAY);
        let level = view(&s, &[3; 32], &p, 3 * DAY).unwrap().level;
        assert_eq!(
            level,
            if i > 6 {
                Level::Public
            } else if i > 3 {
                Level::Ingroup
            } else {
                Level::Circle
            },
            "{i} members left"
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
    let mut s = room(80);
    let t = 80 * 3_600;
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
            t,
        );
        s = apply(&s, &r, t).0;
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
        t,
    );
    assert!(matches!(
        prepare(
            &s,
            &r,
            &SignedPolicy::new(&policy()),
            &TestAuthority,
            t,
            128
        ),
        Err(Error::Capacity)
    ));
    // Decided 2026-10-13: user-facing limit 250 for a public room.
    assert_eq!(policy().cap, 250);
    let s = room(250);
    let t = 250 * 3_600;
    let r = request(
        &s,
        Command::Join {
            group: [3; 32],
            member: "m250".into(),
            vouches: BTreeSet::new(),
        },
        "m250",
        members(250, 251),
        true,
        t,
    );
    assert!(matches!(
        prepare(
            &s,
            &r,
            &SignedPolicy::new(&policy()),
            &TestAuthority,
            t,
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
