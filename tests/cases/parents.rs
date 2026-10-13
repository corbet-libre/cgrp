//! Lower-owner refusal tests. Genuine invitation/MLS import is tested by its
//! Threads consumer; no accepting parent verifier is introduced here.
use crate::support::*;
use cgrp::*;

fn invitation_request(state: &Snapshot) -> Request {
    request(
        state,
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
    )
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn decoded_parent_and_real_consents_do_not_replace_invitation_authority() {
    let existing = circle(12);
    let command = invitation_request(&existing);
    let parent = existing.group_state(&[1; 32]).unwrap();
    let parent = GroupState::decode(&parent.canonical_bytes().unwrap()).unwrap();
    let newcomer = Snapshot::empty(existing.community().into());
    assert!(matches!(
        prepare_with_parents(
            &newcomer,
            &command,
            &[parent],
            &SignedPolicy::new(&policy()),
            &TestAuthority,
            2,
            128,
        ),
        Err(Error::Unavailable)
    ));
    assert_eq!(newcomer.revision(), 0);
    assert!(newcomer.group_state(&[1; 32]).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn present_parent_cannot_be_replaced_and_empty_import_preserves_original_candidate() {
    let existing = circle(12);
    let command = invitation_request(&existing);
    let source = SignedPolicy::new(&policy());
    let parent = existing.group_state(&[1; 32]).unwrap();
    assert!(matches!(
        prepare_with_parents(
            &existing,
            &command,
            &[parent],
            &source,
            &TestAuthority,
            2,
            128
        ),
        Err(Error::Conflict)
    ));
    let original = prepare(&existing, &command, &source, &TestAuthority, 2, 128).unwrap();
    let compatible =
        prepare_with_parents(&existing, &command, &[], &source, &TestAuthority, 2, 128).unwrap();
    compatible.check_base(&existing).unwrap();
    compatible.revalidate(&source, &TestAuthority, 2).unwrap();
    assert_eq!(
        original.prepare_effects()[0].group_state(),
        compatible.prepare_effects()[0].group_state()
    );
    let unrelated = Snapshot::empty(existing.community().into());
    assert_eq!(compatible.check_base(&unrelated), Err(Error::Conflict));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn missing_extra_wrong_and_over_budget_imports_refuse_without_changing_base() {
    let existing = circle(12);
    let mut command = invitation_request(&existing);
    let source = SignedPolicy::new(&policy());
    let parent = existing.group_state(&[1; 32]).unwrap();
    let newcomer = Snapshot::empty(existing.community().into());
    let frozen = serde_json::to_vec(&newcomer).unwrap();
    assert!(
        prepare_with_parents(&newcomer, &command, &[], &source, &TestAuthority, 2, 128).is_err()
    );
    assert!(
        prepare_with_parents(
            &newcomer,
            &command,
            &[parent.clone(), parent.clone()],
            &source,
            &TestAuthority,
            2,
            128
        )
        .is_err()
    );
    assert!(matches!(
        prepare_with_parents(
            &newcomer,
            &command,
            std::slice::from_ref(&parent),
            &source,
            &TestAuthority,
            2,
            0
        ),
        Err(Error::Capacity)
    ));
    command.parents[0].commitment[0] ^= 1;
    assert!(matches!(
        prepare_with_parents(
            &newcomer,
            &command,
            &[parent],
            &source,
            &TestAuthority,
            2,
            128
        ),
        Err(Error::Authority)
    ));
    assert_eq!(serde_json::to_vec(&newcomer).unwrap(), frozen);
}
