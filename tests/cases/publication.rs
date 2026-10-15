//! Publication repeats the original signed checks after preparation.
use crate::support::*;
use cgrp::*;
use std::collections::BTreeSet;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn identical_consent_uses_group_parent_not_local_journal_revision() {
    let a = circle(12);
    let tick = request(&a, Command::Tick, "m0", BTreeSet::new(), false, 1);
    let b = apply(&a, &tick, 1).0;
    let unrelated = request(
        &b,
        Command::Create {
            id: [9; 32],
            members: members(0, 3),
        },
        "m0",
        members(0, 3),
        false,
        1,
    );
    let b = apply(&b, &unrelated, 1).0;
    assert_ne!(a.revision(), b.revision());
    assert_eq!(a.group_state(&[1; 32]), b.group_state(&[1; 32]));
    let command = request(
        &a,
        Command::Fork {
            id: [2; 32],
            parents: vec![[1; 32]],
            members: members(0, 13),
            kind: ForkKind::Add,
        },
        "m0",
        members(0, 13),
        false,
        2,
    );
    // The exact same signatures, operation, time and parent commitments reach
    // both local journals. This test does not import a missing newcomer parent.
    let source = SignedPolicy::new(&policy());
    let ac = prepare(&a, &command, &source, &TestAuthority, 2, 128).unwrap();
    let bc = prepare(&b, &command, &source, &TestAuthority, 2, 128).unwrap();
    assert_eq!(bc.check_base(&a), Err(Error::Conflict));
    let target = |candidate: &Candidate| {
        candidate
            .prepare_effects()
            .into_iter()
            .find(|e| matches!(e.event(), Effect::Membership { group, .. } if group == &[2; 32]))
            .unwrap()
            .group_state()
            .clone()
    };
    assert_eq!(target(&ac), target(&bc));
    assert_eq!(target(&ac).revision(), 1);
    let next = apply(&b, &command, 2).0;
    assert_eq!(next.group_state(&[9; 32]), b.group_state(&[9; 32]));
    let mut tampered = command.clone();
    tampered.parents[0].commitment[0] ^= 1;
    assert!(matches!(
        prepare(&a, &tampered, &source, &TestAuthority, 2, 128),
        Err(Error::Conflict)
    ));
    let mut backdated = command.clone();
    backdated.effective_at = 1;
    assert!(matches!(
        prepare(&a, &backdated, &source, &TestAuthority, 2, 128),
        Err(Error::Authority)
    ));
    assert!(
        prepare(
            &Snapshot::empty("test-community".into()),
            &command,
            &source,
            &TestAuthority,
            2,
            128
        )
        .is_err()
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn group_state_encoding_is_bounded_versioned_and_scope_bound() {
    let state = circle(3).group_state(&[1; 32]).unwrap();
    let bytes = state.canonical_bytes().unwrap();
    assert_eq!(GroupState::decode(&bytes).unwrap(), state);
    assert_eq!(state.community(), "test-community");
    assert_eq!(state.policy_epoch(), 1);
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(GroupState::decode(text.replace("\"version\":1", "\"version\":2").as_bytes()).is_err());
    assert!(
        GroupState::decode(
            text.replace("\"version\":1", "\"version\":1,\"version\":1")
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        GroupState::decode(
            text.replace("\"community\":", "\"unknown\":0,\"community\":")
                .as_bytes()
        )
        .is_err()
    );
    assert!(GroupState::decode(&[0; 65_537]).is_err());
    let mut extra = bytes;
    extra.push(b' ');
    assert!(GroupState::decode(&extra).is_err());
    let foreign =
        GroupState::decode(text.replace("test-community", "other-community").as_bytes()).unwrap();
    assert_ne!(foreign.commitment().unwrap(), state.commitment().unwrap());
}

struct Revocation(u8);
impl Authority for Revocation {
    fn consent(&self, consent: &Consent, now: u64) -> Result<()> {
        TestAuthority.consent(consent, now)?;
        if self.0 == 0 && now >= 11 {
            return Err(Error::Authority);
        }
        Ok(())
    }
    fn contact(&self, community: &str, member: &str, contact: &str, now: u64) -> Result<()> {
        TestAuthority.contact(community, member, contact, now)?;
        if self.0 == 1 && now >= 11 {
            return Err(Error::Authority);
        }
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn current_consent_contacts_and_exact_policy_are_required() {
    let base = Snapshot::empty("test-community".into());
    let source = SignedPolicy::new(&policy());
    for kind in 0..2 {
        let request = request(
            &base,
            Command::Create {
                id: [1; 32],
                members: members(0, 3),
            },
            "m0",
            members(0, 3),
            false,
            10,
        );
        let candidate = prepare(&base, &request, &source, &Revocation(kind), 10, 128).unwrap();
        candidate.check_base(&base).unwrap();
        assert_eq!(
            candidate.check_base(&Snapshot::empty("other-community".into())),
            Err(Error::Conflict)
        );
        candidate
            .revalidate(&source, &Revocation(kind), 10)
            .unwrap();
        candidate.revalidate(&source, &TestAuthority, 11).unwrap();
        assert_eq!(
            candidate.revalidate(&source, &Revocation(kind), 11),
            Err(Error::Authority)
        );
        assert_eq!(
            candidate.revalidate(&source, &TestAuthority, 9),
            Err(Error::Clock)
        );
        assert_eq!(
            candidate.revalidate(&source, &TestAuthority, 10 + DAY),
            Err(Error::Authority)
        );
        let mut changed = policy();
        changed.bands[0].posts_per_hour += 1;
        assert_eq!(
            candidate.revalidate(&SignedPolicy::new(&changed), &TestAuthority, 11),
            Err(Error::Authority)
        );
        let mut invalid = SignedPolicy::new(&policy());
        invalid.corrupt();
        assert_eq!(
            candidate.revalidate(&invalid, &TestAuthority, 11),
            Err(Error::Authority)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn pending_opening_cannot_publish_across_its_original_deadline() {
    let base = room(42);
    let deadline = 21 * DAY;
    let request = request(
        &base,
        Command::Tick,
        "m0",
        BTreeSet::new(),
        false,
        deadline - 1,
    );
    let source = SignedPolicy::new(&policy());
    let candidate = prepare(&base, &request, &source, &TestAuthority, deadline - 1, 128).unwrap();
    candidate
        .revalidate(&source, &TestAuthority, deadline - 1)
        .unwrap();
    assert_eq!(
        candidate.revalidate(&source, &TestAuthority, deadline),
        Err(Error::Authority)
    );
    let mut store = Store::new(&base);
    assert!(matches!(
        futures::executor::block_on(candidate.persist(&mut store, deadline)),
        Err(Error::Authority)
    ));
    assert_eq!(store.read(), base);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn equal_local_revisions_do_not_make_different_membership_interchangeable() {
    let base = circle(3);
    let other = circle(4);
    assert_eq!(base.revision(), other.revision());
    let request = request(&base, Command::Tick, "m0", BTreeSet::new(), false, 1);
    let candidate = prepare(
        &base,
        &request,
        &SignedPolicy::new(&policy()),
        &TestAuthority,
        1,
        128,
    )
    .unwrap();
    candidate.check_base(&base).unwrap();
    assert_eq!(candidate.check_base(&other), Err(Error::Conflict));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn canonical_snapshot_uses_the_real_encrypted_store() {
    // `circle` drives its own executor, so it must run outside the async block.
    let expected = circle(3);
    futures::executor::block_on(async {
        let prf = ckmg::passkey::PrfOutput::from_bytes(&[41; 32]).unwrap();
        let cipher = ckmg::passkey::store_cipher(&prf, "test-community").unwrap();
        let backend = cwst::backend::Memory::new();
        let mut store = cwst::Store::create(backend.clone(), &cipher, "test-community")
            .await
            .unwrap();
        assert_eq!(
            Snapshot::load("test-community", &store).unwrap().revision(),
            0
        );
        assert_eq!(
            Snapshot::load("other-community", &store),
            Err(Error::Authority)
        );
        for (index, bytes) in [
            b"invalid".to_vec(),
            postcard::to_allocvec(&Snapshot::empty("other-community".into())).unwrap(),
            postcard::to_allocvec(&expected).unwrap(),
        ]
        .into_iter()
        .enumerate()
        {
            store
                .commit(
                    store.version().unwrap(),
                    [(index + 1) as u8; 32],
                    &[cwst::Change::Put {
                        owner: "cgrp",
                        key: b"snapshot.v1",
                        value: &bytes,
                    }],
                    &[],
                )
                .await
                .unwrap();
            match index {
                0 => assert_eq!(
                    Snapshot::load("test-community", &store),
                    Err(Error::Invalid)
                ),
                1 => assert_eq!(
                    Snapshot::load("test-community", &store),
                    Err(Error::Authority)
                ),
                _ => assert_eq!(Snapshot::load("test-community", &store).unwrap(), expected),
            }
        }
        let reopened = cwst::Store::open(backend, &cipher, "test-community")
            .await
            .unwrap();
        assert_eq!(
            Snapshot::load("test-community", &reopened).unwrap(),
            expected
        );
    });
}
