use crate::support::*;
use cgrp::*;
use std::collections::BTreeSet;

const G: Id = [3; 32];
const CHILD: Id = [5; 32];
const NOW: u64 = 500_000;
const COMMUNITY: &str = "test-community";

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

fn share_to(from: &Listings, snapshot: &Snapshot, to: &str) -> Listings {
    let mut other = Listings::new(COMMUNITY, to);
    other.adopt(snapshot, &from.share(&G).unwrap()).unwrap();
    other
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn key_creation_requires_a_public_room_and_membership() {
    let s = room(43, false);
    let mut l = Listings::new(COMMUNITY, "m0");
    assert_eq!(l.room_id(&G), Err(Error::Authority));
    assert_eq!(l.share(&G).unwrap_err(), Error::Authority);
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
    let seed = room(60, true);
    assert!(Listings::new(COMMUNITY, "m5").create(&seed, &G).is_ok());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn entries_are_deterministic_monotone_and_bounded() {
    let s = room(43, false);
    let mut l = Listings::new(COMMUNITY, "m0");
    let public = l.create(&s, &G).unwrap();
    let revision = s.group_state(&G).unwrap().revision();
    let e = l
        .sign_listing(&s, &G, "Hike", "Weekend walks", NOW, false)
        .unwrap();
    assert_eq!(e.entry.key, public);
    assert_eq!(e.room(), l.room_id(&G).unwrap());
    assert!(!e.entry.withdrawn);
    assert_eq!(e.entry.counter, ((NOW / LISTING_WINDOW) << 32) | revision);
    assert_eq!(
        e.entry.expires_ms,
        (NOW / LISTING_WINDOW + 2) * LISTING_WINDOW * 1000
    );
    assert!(e.entry.expires_ms > NOW * 1000);
    assert!(e.entry.expires_ms <= NOW * 1000 + 7 * DAY * 1000);
    assert!(REPUBLISH_SECONDS <= DAY);

    // Same window, same content: identical entry, also from another member.
    assert!(
        e == l
            .sign_listing(&s, &G, "Hike", "Weekend walks", NOW + 3_600, false)
            .unwrap()
    );
    let mut other = share_to(&l, &s, "m1");
    assert!(
        e == other
            .sign_listing(&s, &G, "Hike", "Weekend walks", NOW + 7_200, false)
            .unwrap()
    );

    // A different description in the same window and revision cannot be signed.
    assert_eq!(
        l.sign_listing(&s, &G, "Hike", "Other", NOW, false)
            .unwrap_err(),
        Error::Conflict
    );
    // A new window is strictly newer, and then older windows are refused.
    let later = l
        .sign_listing(&s, &G, "Hike", "Other", NOW + LISTING_WINDOW, false)
        .unwrap();
    assert!(later.entry.counter > e.entry.counter);
    assert_eq!(
        l.sign_listing(&s, &G, "Hike", "Walks", NOW, false)
            .unwrap_err(),
        Error::Conflict
    );

    // Bounds and authority.
    assert_eq!(
        l.sign_listing(&s, &G, &"n".repeat(65), "", NOW, false)
            .unwrap_err(),
        Error::Capacity
    );
    assert_eq!(
        l.sign_listing(&s, &G, "n", &"d".repeat(513), NOW, false)
            .unwrap_err(),
        Error::Capacity
    );
    assert_eq!(
        l.sign_listing(&s, &G, "n", "d", 1, false).unwrap_err(),
        Error::Clock
    );
    assert_eq!(
        l.sign_listing(&s, &G, "n", "d", 1 << 60, false)
            .unwrap_err(),
        Error::Clock
    );
    assert_eq!(
        l.sign_listing(&Snapshot::empty("other".into()), &G, "n", "d", NOW, false)
            .unwrap_err(),
        Error::Authority
    );
    assert_eq!(
        l.sign_listing(&s, &[9; 32], "n", "d", NOW, false)
            .unwrap_err(),
        Error::Invalid
    );
    assert_eq!(
        l.sign_listing(&s, &G, "n", "d", NOW, true).unwrap_err(),
        Error::Authority
    );
    assert_eq!(
        l.sign_listing(&s, &[2; 32], "n", "d", NOW, false)
            .unwrap_err(),
        Error::Authority
    );
    assert_eq!(
        Listings::new(COMMUNITY, "m99")
            .sign_listing(&s, &G, "n", "d", NOW, false)
            .unwrap_err(),
        Error::Authority
    );
    assert_eq!(
        Listings::new(COMMUNITY, "m0")
            .sign_listing(&s, &G, "n", "d", NOW, false)
            .unwrap_err(),
        Error::Authority
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn dropping_to_an_ingroup_allows_a_newer_tombstone_and_leavers_lose_the_key() {
    let s = room(43, false);
    let mut l = Listings::new(COMMUNITY, "m0");
    l.create(&s, &G).unwrap();
    let mut leaver = share_to(&l, &s, "m42");
    let live = l.sign_listing(&s, &G, "Hike", "Walks", NOW, false).unwrap();
    let mut t = NOW;
    let mut dropped = s.clone();
    for i in (36..43).rev() {
        t += 1;
        dropped = leave(&dropped, G, &format!("m{i}"), t);
    }
    let tomb = l.sign_listing(&dropped, &G, "", "", t, true).unwrap();
    assert!(tomb.entry.withdrawn);
    assert!(tomb.entry.counter > live.entry.counter);
    assert_eq!(tomb.room(), live.room());
    // The group is no longer public, so it cannot be listed again.
    assert_eq!(
        l.sign_listing(&dropped, &G, "Hike", "Walks", t, false)
            .unwrap_err(),
        Error::Authority
    );
    // The leaver holds the key but may not sign; pruning wipes it.
    assert_eq!(
        leaver
            .sign_listing(&dropped, &G, "", "", t, true)
            .unwrap_err(),
        Error::Authority
    );
    leaver.prune(&dropped);
    assert_eq!(leaver.room_id(&G), Err(Error::Authority));
    l.prune(&dropped);
    assert!(l.room_id(&G).is_ok());
    l.prune(&Snapshot::empty(COMMUNITY.into()));
    assert_eq!(l.room_id(&G), Err(Error::Authority));
    let mut again = share_to(&leaver_source(&s), &s, "m3");
    again.retire(&G);
    assert_eq!(again.room_id(&G), Err(Error::Authority));
}

fn leaver_source(s: &Snapshot) -> Listings {
    let mut l = Listings::new(COMMUNITY, "m0");
    l.create(s, &G).unwrap();
    l
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn shares_converge_on_the_lowest_key_and_persist() {
    let s = room(43, false);
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
    let mut dropped = s.clone();
    let mut t = NOW;
    for i in (36..43).rev() {
        t += 1;
        dropped = leave(&dropped, G, &format!("m{i}"), t);
    }
    assert_eq!(c.adopt(&dropped, &sa), Err(Error::Authority));

    let bytes = a.encode().unwrap();
    let back = Listings::decode(COMMUNITY, "m0", &bytes).unwrap();
    assert_eq!(back.room_id(&G), a.room_id(&G));
    assert_eq!(
        Listings::decode("other", "m0", &bytes).unwrap_err(),
        Error::Authority
    );
    assert_eq!(
        Listings::decode(COMMUNITY, "m7", &bytes).unwrap_err(),
        Error::Authority
    );
    assert_eq!(
        Listings::decode(COMMUNITY, "m0", &[1, 2, 3]).unwrap_err(),
        Error::Invalid
    );
}

fn forked(parent_remaining_leavers: std::ops::Range<usize>) -> (Snapshot, u64) {
    let s = room(100, false);
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
fn the_larger_fork_keeps_the_key_after_the_wait() {
    let wait = 72 * 3_600;
    // The child is smaller: the parent keeps the key, even after the wait.
    let (even, t0) = forked(0..0);
    let mut l = Listings::new(COMMUNITY, "m0");
    l.create(&even, &G).unwrap();
    let room_id = l.room_id(&G).unwrap();
    assert_eq!(
        l.fork(&even, (&G, &CHILD), (t0, wait), t0 + wait + 1),
        Ok(Keeper::Parent)
    );
    assert_eq!(l.room_id(&G).unwrap(), room_id);

    // The child becomes larger: still the parent before the wait is over.
    let (s, t0) = forked(50..80);
    assert_eq!(
        l.fork(&s, (&G, &CHILD), (t0, wait), t0 + wait - 1),
        Ok(Keeper::Parent)
    );
    assert_eq!(l.room_id(&CHILD), Err(Error::Authority));
    // After the wait the key moves to the child on this device.
    let decided = t0 + wait;
    assert_eq!(
        l.fork(&s, (&G, &CHILD), (t0, wait), decided),
        Ok(Keeper::Child)
    );
    assert_eq!(l.room_id(&CHILD).unwrap(), room_id);
    assert_eq!(l.room_id(&G), Err(Error::Authority));
    let e = l
        .sign_listing(&s, &CHILD, "Hike", "Walks", decided, false)
        .unwrap();
    assert_eq!(e.entry.counter >> 32, decided / LISTING_WINDOW + 1);
    assert_eq!(e.room(), room_id);

    // A member who stayed only in the parent drops the key; a holder without a key is unaffected.
    let mut stayer = Listings::new(COMMUNITY, "m90");
    let source = leaver_source(&s);
    stayer.adopt(&s, &source.share(&G).unwrap()).unwrap();
    assert_eq!(
        stayer.fork(&s, (&G, &CHILD), (t0, wait), decided),
        Ok(Keeper::Child)
    );
    assert_eq!(stayer.room_id(&G), Err(Error::Authority));
    assert_eq!(stayer.room_id(&CHILD), Err(Error::Authority));
    assert_eq!(
        Listings::new(COMMUNITY, "m1").fork(&s, (&G, &CHILD), (t0, wait), decided),
        Ok(Keeper::Child)
    );

    // Unknown groups are refused.
    assert_eq!(
        l.fork(&s, (&[9; 32], &CHILD), (t0, wait), decided),
        Err(Error::Invalid)
    );
    assert_eq!(
        l.fork(&s, (&G, &[9; 32]), (t0, wait), decided),
        Err(Error::Invalid)
    );
}
