use crate::support::*;
use cgrp::*;
use std::collections::BTreeSet;

#[track_caller]
fn rejected(s: &Snapshot, r: &Request, p: &Policy, now: u64, expected: Error) {
    assert!(
        matches!(prepare(s, r, &SignedPolicy::new(p), &TestAuthority, now, 128), Err(e) if e == expected)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn invalid_policy_never_becomes_authority() {
    let p = policy();
    let cases: Vec<PolicyEdit> = vec![
        Box::new(|p| p.valid_until = 0),
        Box::new(|p| p.seats.enabled = true),
        Box::new(|p| p.cap = 257),
        Box::new(|p| p.cap = 42),
        Box::new(|p| p.circle_max = 13),
        Box::new(|p| p.ingroup_max = 41),
        Box::new(|p| p.shrink_public = 37),
        Box::new(|p| p.shrink_ingroup = 11),
        Box::new(|p| p.split_public_min = 36),
        Box::new(|p| p.split_public_min = 44),
        Box::new(|p| p.seats.minimum = f64::NAN),
        Box::new(|p| p.seats.large = -1.0),
        Box::new(|p| p.seats.low = 2),
        Box::new(|p| p.seats.high = 250),
        Box::new(|p| p.seats.low = 61),
        Box::new(|p| p.modularity = 1.1),
        Box::new(|p| p.overlap = 1.1),
        Box::new(|p| p.bands[0].lower = 4),
        Box::new(|p| p.bands[1].enter_up = 5),
        Box::new(|p| p.bands[2].leave_down = 9),
        Box::new(|p| p.bands[0].posts_per_hour = 0),
        Box::new(|p| p.bands[0].burst = 0),
        Box::new(|p| p.bands[0].vouches = 3),
    ];
    for edit in cases {
        let mut bad = p.clone();
        edit(&mut bad);
        assert_eq!(bad.validate(0), Err(Error::Policy));
    }
    // The technical ceiling (2^8) is accepted; one more is refused above.
    let mut ceiling = p.clone();
    ceiling.cap = 256;
    assert_eq!(ceiling.validate(0), Ok(()));
    assert_eq!(p.band(20, 9), Err(Error::Invalid));
    assert_eq!(p.band(0, 8).unwrap(), 0);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn consent_scope_revision_visibility_and_expiry_are_bound() {
    let s = Snapshot::empty("test-community".into());
    let p = policy();
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
    let edits: Vec<ConsentEdit> = vec![
        Box::new(|c| c.community = "foreign".into()),
        Box::new(|c| c.operation = [9; 32]),
        Box::new(|c| c.signature.clear()),
        Box::new(|c| c.policy_epoch = 2),
        Box::new(|c| c.command_digest = [9; 32]),
        Box::new(|c| c.valid_until = 0),
        Box::new(|c| c.member.clear()),
        Box::new(|c| c.member = "a".repeat(201)),
    ];
    for edit in edits {
        let mut r = good.clone();
        edit(&mut r.consents[0]);
        rejected(&s, &r, &p, 0, Error::Authority);
    }
    let mut r = good.clone();
    r.consents.push(r.consents[0].clone());
    rejected(&s, &r, &p, 0, Error::Authority);
    let mut r = good.clone();
    r.consents.remove(0);
    rejected(&s, &r, &p, 0, Error::Authority);
    let mut r = good.clone();
    r.actor.clear();
    rejected(&s, &r, &p, 0, Error::Invalid);
    let mut r = good.clone();
    r.actor = "a".repeat(201);
    rejected(&s, &r, &p, 0, Error::Invalid);
    let mut r = good.clone();
    r.consents = vec![r.consents[0].clone(); usize::from(p.cap) + 1];
    rejected(&s, &r, &p, 0, Error::Invalid);
    assert!(matches!(
        prepare(&s, &good, &SignedPolicy::new(&p), &TestAuthority, 0, 0),
        Err(Error::Capacity)
    ));
    let s = apply(&s, &good, 0).0;
    let r = request(
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
    rejected(&s, &r, &p, 0, Error::Conflict);
    let mut r = request(&s, Command::Tick, "m0", BTreeSet::new(), false, 1);
    r.operation = good.operation;
    rejected(&s, &r, &p, 1, Error::Conflict);
    let mut old = p.clone();
    old.epoch = 0;
    rejected(
        &s,
        &request(&s, Command::Tick, "m0", BTreeSet::new(), false, 1),
        &old,
        1,
        Error::Policy,
    );
    let (s, effects) = apply(
        &s,
        &request(&s, Command::Tick, "m0", BTreeSet::new(), false, 10),
        10,
    );
    assert!(effects.is_empty());
    rejected(
        &s,
        &request(&s, Command::Tick, "m0", BTreeSet::new(), false, 9),
        &p,
        9,
        Error::Clock,
    );
    assert_eq!(view(&s, &[8; 32], &p, 10), Err(Error::Invalid));
    assert_eq!(s.members(&[8; 32]), Err(Error::Invalid));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn creations_and_private_joins_require_real_consent_and_vouches() {
    let s = Snapshot::empty("test-community".into());
    let p = policy();
    for (roster, actor, expected) in [
        (members(0, 2), "m0", Error::Invalid),
        (members(1, 4), "m0", Error::Invalid),
        (members(0, 13), "m0", Error::Invalid),
        (members(0, usize::from(p.cap) + 1), "m0", Error::Capacity),
    ] {
        let consenters = if roster.len() > usize::from(p.cap) {
            members(0, usize::from(p.cap))
        } else {
            roster
                .union(&BTreeSet::from([actor.into()]))
                .cloned()
                .collect()
        };
        let r = request(
            &s,
            Command::Create {
                id: [1; 32],
                members: roster,
            },
            actor,
            consenters,
            false,
            0,
        );
        rejected(&s, &r, &p, 0, expected);
    }
    let roster = BTreeSet::from(["m0".into(), "m1".into(), "outside".into()]);
    let r = request(
        &s,
        Command::Create {
            id: [1; 32],
            members: roster.clone(),
        },
        "m0",
        roster,
        false,
        0,
    );
    rejected(&s, &r, &p, 0, Error::Authority);
    let s = circle(12);
    let r = request(
        &s,
        Command::Join {
            group: [1; 32],
            member: "m12".into(),
            vouches: members(0, 1),
        },
        "m12",
        BTreeSet::from(["m0".into(), "m12".into()]),
        false,
        0,
    );
    rejected(&s, &r, &p, 0, Error::Invalid);
    let s = ingroup(13);
    let r = request(
        &s,
        Command::Join {
            group: [2; 32],
            member: "m13".into(),
            vouches: members(0, 1),
        },
        "m13",
        BTreeSet::from(["m0".into(), "m13".into()]),
        false,
        0,
    );
    let (s, effects) = apply(&s, &r, 0);
    assert!(effects.iter().all(|e| e.community() == "test-community"));
    assert_eq!(s.members(&[2; 32]).unwrap().len(), 14);
    let r = request(
        &s,
        Command::Join {
            group: [2; 32],
            member: "m14".into(),
            vouches: BTreeSet::new(),
        },
        "m14",
        members(14, 15),
        false,
        0,
    );
    rejected(&s, &r, &p, 0, Error::Authority);
    for v in ["m0", "m90"] {
        let r = request(
            &s,
            Command::Join {
                group: [2; 32],
                member: "m14".into(),
                vouches: BTreeSet::from([v.into()]),
            },
            "m14",
            members(14, 15),
            false,
            0,
        );
        rejected(&s, &r, &p, 0, Error::Authority);
    }
    let s = ingroup(42);
    let r = request(
        &s,
        Command::Join {
            group: [2; 32],
            member: "m42".into(),
            vouches: members(0, 2),
        },
        "m42",
        BTreeSet::from(["m0".into(), "m1".into(), "m42".into()]),
        false,
        0,
    );
    rejected(&s, &r, &p, 0, Error::Invalid);
    let s = room_fast(43);
    let r = request(
        &s,
        Command::Join {
            group: [3; 32],
            member: "m43".into(),
            vouches: BTreeSet::new(),
        },
        "m44",
        members(43, 45),
        true,
        0,
    );
    rejected(&s, &r, &p, 0, Error::Authority);
    let r = request(
        &s,
        Command::Join {
            group: [3; 32],
            member: "m0".into(),
            vouches: BTreeSet::new(),
        },
        "m0",
        members(0, 1),
        true,
        0,
    );
    rejected(&s, &r, &p, 0, Error::Conflict);
    let r = request(
        &s,
        Command::Leave { group: [3; 32] },
        "m99",
        members(99, 100),
        false,
        0,
    );
    rejected(&s, &r, &p, 0, Error::Authority);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn malformed_forks_and_exclusion_retarget_boundaries() {
    let p = policy();
    let s = circle(6);
    for (parents, kind, roster, expected) in [
        (vec![], ForkKind::Split, members(0, 3), Error::Invalid),
        (
            vec![[1; 32]; 3],
            ForkKind::Split,
            members(0, 3),
            Error::Invalid,
        ),
        (
            vec![[1; 32]; 2],
            ForkKind::Merge,
            members(0, 3),
            Error::Invalid,
        ),
        (
            vec![[1; 32]],
            ForkKind::Merge,
            members(0, 3),
            Error::Invalid,
        ),
        (vec![[1; 32]], ForkKind::Add, members(0, 3), Error::Invalid),
        (
            vec![[1; 32]],
            ForkKind::Split,
            members(0, 7),
            Error::Invalid,
        ),
        (vec![[1; 32]], ForkKind::Open, members(0, 3), Error::Invalid),
        (
            vec![[1; 32]],
            ForkKind::Exclusion {
                target: "missing".into(),
            },
            members(0, 3),
            Error::Invalid,
        ),
        (
            vec![[1; 32]],
            ForkKind::Exclusion {
                target: "m1".into(),
            },
            members(0, 3),
            Error::Invalid,
        ),
        (
            vec![[1; 32]],
            ForkKind::Exclusion {
                target: "m5".into(),
            },
            BTreeSet::from(["m0".into(), "m1".into(), "m7".into()]),
            Error::Invalid,
        ),
    ] {
        let r = request(
            &s,
            Command::Fork {
                id: [4; 32],
                parents,
                members: roster.clone(),
                kind,
            },
            "m0",
            roster,
            false,
            0,
        );
        rejected(&s, &r, &p, 0, expected);
    }
    let r = request(
        &s,
        Command::Fork {
            id: [4; 32],
            parents: vec![[1; 32]],
            members: members(0, 7),
            kind: ForkKind::Split,
        },
        "m6",
        members(0, 7),
        false,
        0,
    );
    rejected(&s, &r, &p, 0, Error::Authority);
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
    for (time, target, expected) in [
        (DAY, "m4", Some(Error::Conflict)),
        (14 * DAY, "m5", Some(Error::Conflict)),
        (28 * DAY, "m5", None),
    ] {
        let r = request(
            &s,
            Command::Fork {
                id: [5; 32],
                parents: vec![[1; 32]],
                members: members(0, 4),
                kind: ForkKind::Exclusion {
                    target: target.into(),
                },
            },
            "m0",
            members(0, 4),
            false,
            time,
        );
        match expected {
            Some(e) => rejected(&s, &r, &p, time, e),
            None => {
                apply(&s, &r, time);
            }
        }
    }
    let s = ingroup(42);
    let r = request(
        &s,
        Command::Fork {
            id: [4; 32],
            parents: vec![[2; 32]],
            members: members(0, 43),
            kind: ForkKind::Add,
        },
        "m0",
        members(0, 43),
        false,
        0,
    );
    rejected(&s, &r, &p, 0, Error::Invalid);
    let r = request(
        &s,
        Command::Fork {
            id: [4; 32],
            parents: vec![[2; 32]],
            members: members(0, 43),
            kind: ForkKind::Open,
        },
        "m0",
        members(0, 43),
        true,
        0,
    );
    rejected(&s, &r, &p, 0, Error::Invalid);
    let s = room_fast(60);
    for n in [10, 38, 43] {
        let r = request(
            &s,
            Command::Fork {
                id: [4; 32],
                parents: vec![[3; 32]],
                members: members(0, n),
                kind: ForkKind::Split,
            },
            "m0",
            members(0, n),
            n >= 43,
            0,
        );
        let (next, _) = apply(&s, &r, 0);
        assert_eq!(
            view(&next, &[4; 32], &p, 0).unwrap().level,
            if n <= 10 {
                Level::Circle
            } else if n < 43 {
                Level::Ingroup
            } else {
                Level::Public
            }
        );
        assert_eq!(s.members(&[3; 32]).unwrap().len(), 60);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn small_add_large_add_merge_and_opening_join_transitions() {
    let p = policy();
    let s = circle(3);
    let r = request(
        &s,
        Command::Fork {
            id: [4; 32],
            parents: vec![[1; 32]],
            members: members(0, 4),
            kind: ForkKind::Add,
        },
        "m0",
        members(0, 4),
        false,
        0,
    );
    let (s, _) = apply(&s, &r, 0);
    for (parents, roster) in [
        (vec![[1; 32], [4; 32]], members(0, 5)),
        (vec![[1; 32], [4; 32]], members(0, 3)),
    ] {
        let r = request(
            &s,
            Command::Fork {
                id: [5; 32],
                parents,
                members: roster.clone(),
                kind: ForkKind::Merge,
            },
            "m0",
            roster,
            false,
            0,
        );
        if let Command::Fork { members, .. } = &r.command {
            if members.len() == 5 {
                rejected(&s, &r, &p, 0, Error::Invalid);
            } else {
                apply(&s, &r, 0);
            }
        }
    }
    let s = ingroup(13);
    let r = request(
        &s,
        Command::Fork {
            id: [4; 32],
            parents: vec![[1; 32], [2; 32]],
            members: members(0, 3),
            kind: ForkKind::Merge,
        },
        "m0",
        members(0, 3),
        false,
        0,
    );
    rejected(&s, &r, &p, 0, Error::Invalid);
    let r = request(
        &s,
        Command::Fork {
            id: [4; 32],
            parents: vec![[2; 32]],
            members: members(0, 13),
            kind: ForkKind::Open,
        },
        "m0",
        members(0, 13),
        true,
        0,
    );
    let s = apply(&s, &r, 0).0;
    let r = request(
        &s,
        Command::Join {
            group: [4; 32],
            member: "m13".into(),
            vouches: BTreeSet::new(),
        },
        "m13",
        members(13, 14),
        true,
        0,
    );
    let s = apply(&s, &r, 0).0;
    assert_eq!(view(&s, &[4; 32], &p, 0).unwrap().level, Level::Opening);
    let s = room_fast(43);
    let r = request(
        &s,
        Command::Fork {
            id: [4; 32],
            parents: vec![[3; 32]],
            members: members(0, 44),
            kind: ForkKind::Add,
        },
        "m0",
        members(0, 44),
        true,
        0,
    );
    let s = apply(&s, &r, 0).0;
    assert_eq!(view(&s, &[4; 32], &p, 0).unwrap().level, Level::Public);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn preparations_are_bound_and_projection_schemas_come_from_owner_types() {
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
        0,
    );
    let c = prepare(
        &s,
        &r,
        &SignedPolicy::new(&policy()),
        &TestAuthority,
        0,
        128,
    )
    .unwrap();
    let effects = c.prepare_effects();
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].community(), "test-community");
    assert!(matches!(
        effects[0].event(),
        Effect::Membership { revision: 1, .. }
    ));
    let schema = schemars::schema_for!(Request);
    let value = serde_json::to_value(schema).unwrap();
    assert_eq!(value["title"], "Request");
    assert!(value["properties"]["consents"].is_object());
}

type PolicyEdit = Box<dyn Fn(&mut Policy)>;
type ConsentEdit = Box<dyn Fn(&mut Consent)>;
