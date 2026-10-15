use crate::support::*;
use cgrp::*;
use std::collections::BTreeSet;

const G: Id = [3; 32];
const CHILD: Id = [5; 32];
const NOW: u64 = 500_000;
const COMMUNITY: &str = "test-community";
const WAIT: u64 = 72 * 3_600;

fn leave(state: &Snapshot, group: Id, member: &str, now: u64) -> Snapshot {
    let r = request(
        state,
        Command::Leave { group },
        member,
        BTreeSet::from([member.to_string()]),
        false,
        now,
    );
    apply(state, &r, now).0
}

fn try_describe(
    state: &Snapshot,
    group: Id,
    actor: &str,
    (name, description): (&str, &str),
    now: u64,
) -> Result<Snapshot> {
    let r = request(
        state,
        Command::Describe {
            group,
            name: name.into(),
            description: description.into(),
        },
        actor,
        BTreeSet::from([actor.to_string()]),
        false,
        now,
    );
    let candidate = prepare(
        state,
        &r,
        &SignedPolicy::new(&policy()),
        &TestAuthority,
        now,
        128,
    )?;
    let mut store = Store::new(state);
    Ok(futures::executor::block_on(candidate.persist(&mut store, now))?.0)
}

fn named(state: &Snapshot, group: Id, at: u64) -> Snapshot {
    try_describe(state, group, "m0", ("Hike", "Weekend walks"), at).unwrap()
}

fn public_room() -> Snapshot {
    named(&room(43), G, 160_000)
}

fn share_to(from: &Listings, snapshot: &Snapshot, to: &str) -> Listings {
    let mut other = Listings::new(COMMUNITY, to);
    other.adopt(snapshot, &from.share(&G).unwrap()).unwrap();
    other
}

fn drop_to_ingroup(mut s: Snapshot, mut t: u64) -> (Snapshot, u64) {
    for i in (36..43).rev() {
        t += 1;
        s = leave(&s, G, &format!("m{i}"), t);
    }
    (s, t)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn name_and_description_are_ordered_group_state() {
    let s = room(43);
    let before = s.group_state(&G).unwrap().revision();
    let d = named(&s, G, 160_000);
    assert_eq!(d.group_state(&G).unwrap().revision(), before + 1);
    // Re-applying the same text changes nothing; any member may propose.
    let same = try_describe(&d, G, "m1", ("Hike", "Weekend walks"), 160_001).unwrap();
    assert_eq!(
        same.group_state(&G).unwrap().revision(),
        d.group_state(&G).unwrap().revision()
    );
    let other = try_describe(&d, G, "m1", ("Hike!", ""), 160_002).unwrap();
    assert_eq!(
        other.group_state(&G).unwrap().revision(),
        d.group_state(&G).unwrap().revision() + 1
    );
    assert_eq!(
        try_describe(&d, G, "m99", ("a", "b"), 160_001)
            .err()
            .unwrap(),
        Error::Authority
    );
    assert_eq!(
        try_describe(&d, [9; 32], "m0", ("a", "b"), 160_001)
            .err()
            .unwrap(),
        Error::Invalid
    );
    for (name, description) in [
        ("n".repeat(65), String::new()),
        (String::new(), "d".repeat(513)),
        ("tab\t".to_string(), String::new()),
        (String::new(), "nl\n".to_string()),
    ] {
        assert_eq!(
            try_describe(&d, G, "m0", (&name, &description), 160_001)
                .err()
                .unwrap(),
            Error::Invalid
        );
    }
    // A state that carries oversized text never decodes.
    let bytes = String::from_utf8(d.group_state(&G).unwrap().canonical_bytes().unwrap()).unwrap();
    let bad = bytes.replace(
        "\"name\":\"Hike\"",
        &format!("\"name\":\"{}\"", "n".repeat(65)),
    );
    assert_ne!(bad, bytes);
    assert_eq!(
        GroupState::decode(bad.as_bytes()).err().unwrap(),
        Error::Invalid
    );
    assert!(GroupState::decode(bytes.as_bytes()).is_ok());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn key_creation_requires_a_public_room_and_membership() {
    let s = public_room();
    let mut l = Listings::new(COMMUNITY, "m0");
    assert_eq!(l.room_id(&G), Err(Error::Authority));
    assert_eq!(l.share(&G).err().unwrap(), Error::Authority);
    assert_eq!(l.create(&s, &[9; 32]), Err(Error::Invalid));
    assert_eq!(l.create(&s, &[2; 32]), Err(Error::Authority));
    assert_eq!(
        l.create(&Snapshot::empty("other".into()), &G),
        Err(Error::Authority)
    );
    assert_eq!(
        Listings::new(COMMUNITY, "m99").create(&s, &G),
        Err(Error::Authority)
    );
    let public = l.create(&s, &G).unwrap();
    assert_eq!(l.create(&s, &G), Err(Error::Conflict));
    assert_eq!(l.room_id(&G).unwrap(), cmbl::listing::room_id(&public));
    let grown = room_fast(60);
    assert!(Listings::new(COMMUNITY, "m5").create(&grown, &G).is_ok());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn entries_are_deterministic_monotone_and_bounded() {
    let s = public_room();
    let mut l = Listings::new(COMMUNITY, "m0");
    let public = l.create(&s, &G).unwrap();
    let revision = s.group_state(&G).unwrap().revision();
    let e = l.sign_listing(&s, &G, NOW, false).unwrap();
    assert_eq!(e.entry.key, public);
    assert_eq!(e.entry.name, "Hike");
    assert_eq!(e.entry.description, "Weekend walks");
    assert_eq!(e.room(), l.room_id(&G).unwrap());
    assert!(!e.entry.withdrawn);
    assert_eq!(e.entry.counter, ((NOW / LISTING_WINDOW) << 32) | revision);
    assert_eq!(
        e.entry.expires_ms,
        (NOW / LISTING_WINDOW + 2) * LISTING_WINDOW * 1000
    );
    assert!(e.entry.expires_ms > NOW * 1000);
    assert!(e.entry.expires_ms <= NOW * 1000 + 7 * DAY * 1000);

    // Same window, same content: identical entry, also from another member.
    assert!(e == l.sign_listing(&s, &G, NOW + 3_600, false).unwrap());
    let mut other = share_to(&l, &s, "m1");
    assert!(e == other.sign_listing(&s, &G, NOW + 7_200, false).unwrap());

    // A different text in the same window needs a new revision, which is newer.
    let d = try_describe(&s, G, "m0", ("Hike", "Other"), 400_000).unwrap();
    let newer = l.sign_listing(&d, &G, NOW, false).unwrap();
    assert!(newer.entry.counter > e.entry.counter);
    assert_eq!(
        l.sign_listing(&s, &G, NOW, false).err().unwrap(),
        Error::Conflict
    );
    // A new window is strictly newer too.
    let later = l.sign_listing(&d, &G, NOW + LISTING_WINDOW, false).unwrap();
    assert!(later.entry.counter > newer.entry.counter);

    // A room without a name cannot be listed.
    let unnamed = room(43);
    let mut u = Listings::new(COMMUNITY, "m0");
    u.create(&unnamed, &G).unwrap();
    assert_eq!(
        u.sign_listing(&unnamed, &G, NOW, false).err().unwrap(),
        Error::Invalid
    );

    // Bounds and authority.
    assert_eq!(
        l.sign_listing(&s, &G, 1, false).err().unwrap(),
        Error::Clock
    );
    assert_eq!(
        l.sign_listing(&s, &G, 1 << 60, false).err().unwrap(),
        Error::Clock
    );
    assert_eq!(
        l.sign_listing(&Snapshot::empty("other".into()), &G, NOW, false)
            .err()
            .unwrap(),
        Error::Authority
    );
    assert_eq!(
        l.sign_listing(&s, &[9; 32], NOW, false).err().unwrap(),
        Error::Invalid
    );
    assert_eq!(
        l.sign_listing(&s, &G, NOW, true).err().unwrap(),
        Error::Authority
    );
    assert_eq!(
        l.sign_listing(&s, &[2; 32], NOW, false).err().unwrap(),
        Error::Authority
    );
    assert_eq!(
        Listings::new(COMMUNITY, "m99")
            .sign_listing(&s, &G, NOW, false)
            .err()
            .unwrap(),
        Error::Authority
    );
    assert_eq!(
        Listings::new(COMMUNITY, "m0")
            .sign_listing(&s, &G, NOW, false)
            .err()
            .unwrap(),
        Error::Authority
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn dropping_to_an_ingroup_allows_a_newer_tombstone_and_leavers_lose_the_key() {
    let s = public_room();
    let mut l = Listings::new(COMMUNITY, "m0");
    l.create(&s, &G).unwrap();
    let mut leaver = share_to(&l, &s, "m42");
    let live = l.sign_listing(&s, &G, NOW, false).unwrap();
    let (dropped, t) = drop_to_ingroup(s.clone(), NOW);
    let tomb = l.sign_listing(&dropped, &G, t, true).unwrap();
    assert!(tomb.entry.withdrawn);
    assert!(tomb.entry.counter > live.entry.counter);
    assert_eq!(tomb.room(), live.room());
    // The group is no longer public, so it cannot be listed again.
    assert_eq!(
        l.sign_listing(&dropped, &G, t, false).err().unwrap(),
        Error::Authority
    );
    // The leaver holds the key but may not sign; pruning wipes it.
    assert_eq!(
        leaver.sign_listing(&dropped, &G, t, true).err().unwrap(),
        Error::Authority
    );
    leaver.prune(&dropped);
    assert_eq!(leaver.room_id(&G), Err(Error::Authority));
    l.prune(&dropped);
    assert!(l.room_id(&G).is_ok());
    l.retire(&G);
    assert_eq!(l.room_id(&G), Err(Error::Authority));
    let mut gone = share_to(&leaver_source(&s), &s, "m3");
    gone.prune(&Snapshot::empty(COMMUNITY.into()));
    assert_eq!(gone.room_id(&G), Err(Error::Authority));
}

fn leaver_source(s: &Snapshot) -> Listings {
    let mut l = Listings::new(COMMUNITY, "m0");
    l.create(s, &G).unwrap();
    l
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn shares_converge_on_the_lowest_key_and_persist() {
    let s = public_room();
    let mut a = Listings::new(COMMUNITY, "m0");
    let mut b = Listings::new(COMMUNITY, "m1");
    let ka = a.create(&s, &G).unwrap();
    let kb = b.create(&s, &G).unwrap();
    let (sa, sb) = (a.share(&G).unwrap(), b.share(&G).unwrap());
    a.adopt(&s, &sb).unwrap();
    b.adopt(&s, &sa).unwrap();
    a.adopt(&s, &sa).unwrap();
    let lowest = ka.min(kb);
    assert_eq!(a.room_id(&G).unwrap(), cmbl::listing::room_id(&lowest));
    assert_eq!(b.room_id(&G).unwrap(), a.room_id(&G).unwrap());
    assert_eq!(format!("{sa:?}"), "ListingShare(redacted)");
    assert!(!format!("{a:?}").contains("secret"));

    let mut foreign = Listings::new("other", "m2");
    assert_eq!(foreign.adopt(&s, &sa), Err(Error::Authority));
    let mut c = Listings::new(COMMUNITY, "m2");
    assert_eq!(
        c.adopt(&Snapshot::empty(COMMUNITY.into()), &sa),
        Err(Error::Invalid)
    );
    let (dropped, _) = drop_to_ingroup(s.clone(), NOW);
    assert_eq!(c.adopt(&dropped, &sa), Err(Error::Authority));

    let bytes = a.encode().unwrap();
    let back = Listings::decode(COMMUNITY, "m0", &bytes).unwrap();
    assert_eq!(back.room_id(&G), a.room_id(&G));
    assert_eq!(
        Listings::decode("other", "m0", &bytes).err().unwrap(),
        Error::Authority
    );
    assert_eq!(
        Listings::decode(COMMUNITY, "m7", &bytes).err().unwrap(),
        Error::Authority
    );
    assert_eq!(
        Listings::decode(COMMUNITY, "m0", &[1, 2, 3]).err().unwrap(),
        Error::Invalid
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_departure_rotates_the_key_at_the_next_window_boundary() {
    let s = public_room();
    let mut l = Listings::new(COMMUNITY, "m0");
    l.create(&s, &G).unwrap();
    let old_room = l.room_id(&G).unwrap();
    let live = l.sign_listing(&s, &G, NOW, false).unwrap();
    assert!(!l.rotation_due(&s, &G, NOW));
    assert!(!Listings::new(COMMUNITY, "m0").rotation_due(&s, &G, NOW));

    // m42 leaves; rotation waits for the next window boundary (batching).
    let left_at = NOW + 10;
    let after = leave(&s, G, "m42", left_at);
    let boundary = (left_at / LISTING_WINDOW + 1) * LISTING_WINDOW;
    assert!(!l.rotation_due(&after, &G, boundary - 1));
    assert_eq!(
        l.rotate(&after, &G, boundary - 1).err().unwrap(),
        Error::Conflict
    );
    assert!(l.rotation_due(&after, &G, boundary));
    let mut peer = share_to(&l, &after, "m1");
    let r = l.rotate(&after, &G, boundary).unwrap();
    assert!(r.tombstone.entry.withdrawn);
    assert_eq!(r.tombstone.room(), old_room);
    assert!(r.tombstone.entry.counter > live.entry.counter);
    assert_ne!(r.room, old_room);
    assert_eq!(l.room_id(&G).unwrap(), r.room);
    assert!(!l.rotation_due(&after, &G, boundary + 1));

    // The next generation replaces the old key on other members, even when the
    // old key sorts lower; a stale share never replaces it back.
    let stale = peer.share(&G).unwrap();
    peer.adopt(&after, &r.share).unwrap();
    assert_eq!(peer.room_id(&G).unwrap(), r.room);
    peer.adopt(&after, &stale).unwrap();
    assert_eq!(peer.room_id(&G).unwrap(), r.room);
    let e = peer.sign_listing(&after, &G, boundary, false).unwrap();
    assert_eq!(e.room(), r.room);

    // The leaver cannot rotate.
    let mut gone = share_to(&leaver_source(&s), &s, "m42");
    gone.prune(&after);
    assert_eq!(
        gone.rotate(&after, &G, boundary).err().unwrap(),
        Error::Conflict
    );
    // A holder whose rotation became due after losing public status is refused.
    let (dropped, t) = drop_to_ingroup(s.clone(), NOW);
    let mut late = share_to(&leaver_source(&s), &s, "m1");
    let due = (t / LISTING_WINDOW + 1) * LISTING_WINDOW;
    assert!(late.rotation_due(&dropped, &G, due));
    assert_eq!(
        late.rotate(&dropped, &G, due).err().unwrap(),
        Error::Authority
    );
    // Far-future clock overflows the counter.
    let mut big = share_to(&leaver_source(&s), &s, "m1");
    assert_eq!(big.rotate(&after, &G, 1 << 60).err().unwrap(), Error::Clock);
}

fn forked(parent_remaining_leavers: std::ops::Range<usize>) -> (Snapshot, u64) {
    let s = named(&room(100), G, 360_000);
    let t0 = 400_000;
    let r = request(
        &s,
        Command::Fork {
            id: CHILD,
            parents: vec![G],
            members: members(0, 80),
            kind: ForkKind::Split,
        },
        "m0",
        members(0, 80),
        true,
        t0,
    );
    let mut s = apply(&s, &r, t0).0;
    for i in parent_remaining_leavers {
        s = leave(&s, G, &format!("m{i}"), t0 + 1 + i as u64);
    }
    (s, t0)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn the_larger_fork_keeps_the_key_after_the_wait_and_every_fork_rotates() {
    // The child is smaller: the parent keeps the key, even after the wait.
    let (even, t0) = forked(0..0);
    let mut l = Listings::new(COMMUNITY, "m0");
    l.create(&even, &G).unwrap();
    let room_id = l.room_id(&G).unwrap();
    assert_eq!(
        l.fork(&even, (&G, &CHILD), WAIT, t0 + WAIT + 1),
        Ok(Keeper::Parent)
    );
    assert_eq!(l.room_id(&G).unwrap(), room_id);
    // The fork scheduled a rotation for the next window boundary.
    let boundary = (t0 / LISTING_WINDOW + 1) * LISTING_WINDOW;
    assert!(!l.rotation_due(&even, &G, boundary - 1));
    assert!(l.rotation_due(&even, &G, boundary));
    // The child inherited the name and description of the parent.
    let child_entry = {
        let mut c = Listings::new(COMMUNITY, "m0");
        c.create(&even, &CHILD).unwrap();
        c.sign_listing(&even, &CHILD, t0 + 1, false).unwrap()
    };
    assert_eq!(child_entry.entry.name, "Hike");

    // The child becomes larger: still the parent before the wait is over.
    let (s, t0) = forked(50..80);
    assert_eq!(
        l.fork(&s, (&G, &CHILD), WAIT, t0 + WAIT - 1),
        Ok(Keeper::Parent)
    );
    assert_eq!(l.room_id(&CHILD), Err(Error::Authority));
    // After the wait the key moves to the child on this device.
    let decided = t0 + WAIT;
    assert_eq!(l.fork(&s, (&G, &CHILD), WAIT, decided), Ok(Keeper::Child));
    assert_eq!(l.room_id(&CHILD).unwrap(), room_id);
    assert_eq!(l.room_id(&G), Err(Error::Authority));
    let e = l.sign_listing(&s, &CHILD, decided, false).unwrap();
    assert_eq!(e.entry.counter >> 32, decided / LISTING_WINDOW + 1);
    assert_eq!(e.room(), room_id);

    // A member who stayed only in the parent drops the key; a holder without a key is unaffected.
    let mut stayer = Listings::new(COMMUNITY, "m90");
    let source = leaver_source(&s);
    stayer.adopt(&s, &source.share(&G).unwrap()).unwrap();
    assert_eq!(
        stayer.fork(&s, (&G, &CHILD), WAIT, decided),
        Ok(Keeper::Child)
    );
    assert_eq!(stayer.room_id(&G), Err(Error::Authority));
    assert_eq!(stayer.room_id(&CHILD), Err(Error::Authority));
    assert_eq!(
        Listings::new(COMMUNITY, "m1").fork(&s, (&G, &CHILD), WAIT, decided),
        Ok(Keeper::Child)
    );

    // Unknown groups are refused.
    assert_eq!(
        l.fork(&s, (&[9; 32], &CHILD), WAIT, decided),
        Err(Error::Invalid)
    );
    assert_eq!(
        l.fork(&s, (&G, &[9; 32]), WAIT, decided),
        Err(Error::Invalid)
    );
}
