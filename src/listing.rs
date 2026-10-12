//! Per-group listing keys for the forum's public-room listing.
//!
//! A group that is a public room (level `Public`) owns one ed25519 listing key.
//! The forum (`cfrm`/`cmbl`) derives the opaque room identifier from the public
//! half and verifies every listing entry against it, so it learns no identity.
//! The private half exists only on the devices of current members: it is
//! created on one member's device and travels to the others as a
//! [`ListingShare`] over the group's own encrypted channel (Threads). This
//! module neither sends nor stores anything; the caller persists
//! [`Listings::encode`] in the encrypted device store.
//!
//! The name and description are ordinary group state (`Command::Describe`), so
//! the ordered result is what gets signed. After any departure or fork the key
//! is rotated at the next window boundary ([`Listings::rotation_due`],
//! [`Listings::rotate`]): the new key means a new room id, the old entry gets a
//! tombstone and expires. Residual: an ex-member who still holds a valid room
//! pass could keep a ghost entry alive until its lifetime ends.
//!
//! Counters are derived, never chosen: `window << 32 | group revision`, where
//! `window` counts [`LISTING_WINDOW`] spans of wall time. Every member who signs
//! in the same window therefore produces the identical entry (ed25519 is
//! deterministic), so concurrent re-publication never conflicts at the forum,
//! while every ordered group change or new window yields a strictly newer entry.
use crate::{DAY, Error, Group, Id, Level, Result, Snapshot, encode};
use cmbl::listing::{Entry, SignedEntry};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroize;

/// Entries are valid for two to four windows at most, well inside the forum's
/// seven-day limit, and identical within one window.
pub const LISTING_WINDOW: u64 = 2 * DAY;
/// A public room is re-published at least this often so that the forum's
/// volatile entry (default lifetime 24 hours) never lapses while it is public.
pub const REPUBLISH_SECONDS: u64 = DAY;

/// Which fork of a public room keeps the listing and its room identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keeper {
    Parent,
    Child,
}

#[derive(Clone, Serialize, Deserialize)]
struct Held {
    secret: [u8; 32],
    /// Lowest window this key may sign in; raised when the listing is handed to
    /// a fork so the child's counters always exceed the parent's.
    floor_window: u64,
    /// Rotations so far; a higher generation always replaces a lower one.
    generation: u32,
    /// Latest departure/fork time already covered by this key.
    handled: u64,
    /// Latest fork time seen on this device that needs a rotation.
    fork_seen: u64,
    /// Highest counter signed on this device and a digest of its content.
    last: Option<(u64, Id)>,
}

impl Held {
    fn public(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.secret)
            .verifying_key()
            .to_bytes()
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// The private listing key of one group, for transfer to another member over
/// the group's own encrypted channel only. Never log, store or show it.
#[derive(Clone, Serialize, Deserialize)]
pub struct ListingShare {
    pub community: String,
    pub group: Id,
    secret: [u8; 32],
    floor_window: u64,
    generation: u32,
    handled: u64,
}

/// Result of a rotation: the tombstone for the old entry and the new key to
/// share with the other members.
pub struct Rotation {
    pub tombstone: SignedEntry,
    pub share: ListingShare,
    pub room: [u8; 16],
}

impl std::fmt::Debug for ListingShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ListingShare(redacted)")
    }
}

impl Drop for ListingShare {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Listing keys held by this device for the groups it belongs to.
#[derive(Serialize, Deserialize)]
pub struct Listings {
    community: String,
    /// The member string of this device's owner, as in group rosters.
    me: String,
    held: BTreeMap<Id, Held>,
}

impl std::fmt::Debug for Listings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listings")
            .field("community", &self.community)
            .field("groups", &self.held.len())
            .finish()
    }
}

impl Listings {
    pub fn new(community: &str, me: &str) -> Self {
        Self {
            community: community.into(),
            me: me.into(),
            held: BTreeMap::new(),
        }
    }

    /// Encode for the encrypted device store (contains private keys).
    pub fn encode(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::Invalid)
    }

    pub fn decode(community: &str, me: &str, bytes: &[u8]) -> Result<Self> {
        let value: Self = postcard::from_bytes(bytes).map_err(|_| Error::Invalid)?;
        if value.community != community || value.me != me {
            return Err(Error::Authority);
        }
        Ok(value)
    }

    /// Require a public group of this community that this device's owner belongs
    /// to; returns its current revision.
    fn public_member_group<'a>(&self, snapshot: &'a Snapshot, group: &Id) -> Result<&'a Group> {
        if snapshot.community != self.community {
            return Err(Error::Authority);
        }
        let g = snapshot.groups.get(group).ok_or(Error::Invalid)?;
        if g.level != Level::Public || !g.members.contains(&self.me) {
            return Err(Error::Authority);
        }
        Ok(g)
    }

    fn public_member(&self, snapshot: &Snapshot, group: &Id) -> Result<u64> {
        Ok(self.public_member_group(snapshot, group)?.revision)
    }

    /// Create the listing key of a group that is a public room. Returns the
    /// public key. Only a member may create it; a group holds at most one key
    /// on this device.
    pub fn create(&mut self, snapshot: &Snapshot, group: &Id) -> Result<[u8; 32]> {
        self.public_member(snapshot, group)?;
        if self.held.contains_key(group) {
            return Err(Error::Conflict);
        }
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|_| Error::Unavailable)?;
        let held = Held {
            secret,
            floor_window: 0,
            generation: 0,
            handled: self.churn(snapshot, group),
            fork_seen: 0,
            last: None,
        };
        secret.zeroize();
        let public = held.public();
        self.held.insert(*group, held);
        Ok(public)
    }

    fn churn(&self, snapshot: &Snapshot, group: &Id) -> u64 {
        snapshot.groups.get(group).map_or(0, |g| g.churn_at)
    }

    /// The forum's opaque room identifier for this group; room-pass requests use it.
    pub fn room_id(&self, group: &Id) -> Result<[u8; 16]> {
        let held = self.held.get(group).ok_or(Error::Authority)?;
        Ok(cmbl::listing::room_id(&held.public()))
    }

    /// Export the key for a fellow member, to be sent over the group's channel.
    pub fn share(&self, group: &Id) -> Result<ListingShare> {
        let held = self.held.get(group).ok_or(Error::Authority)?;
        Ok(ListingShare {
            community: self.community.clone(),
            group: *group,
            secret: held.secret,
            floor_window: held.floor_window,
            generation: held.generation,
            handled: held.handled,
        })
    }

    /// Accept a key received from a fellow member. The higher rotation
    /// generation wins; between equal generations (two members acting at the
    /// same time) the numerically lowest public key wins on every device.
    pub fn adopt(&mut self, snapshot: &Snapshot, share: &ListingShare) -> Result<()> {
        if share.community != self.community {
            return Err(Error::Authority);
        }
        self.public_member(snapshot, &share.group)?;
        let incoming = Held {
            secret: share.secret,
            floor_window: share.floor_window,
            generation: share.generation,
            handled: share.handled,
            fork_seen: 0,
            last: None,
        };
        if let Some(current) = self.held.get(&share.group)
            && (current.generation, std::cmp::Reverse(current.public()))
                >= (incoming.generation, std::cmp::Reverse(incoming.public()))
        {
            return Ok(());
        }
        self.held.insert(share.group, incoming);
        Ok(())
    }

    /// Sign the listing entry of a group. `now` is wall-clock seconds. Any member
    /// holding the key may sign; the entry for a given window, group revision,
    /// name and description is the same whoever signs it. A tombstone
    /// (`withdrawn`) is allowed only once the group is no longer public.
    pub fn sign_listing(
        &mut self,
        snapshot: &Snapshot,
        group: &Id,
        now: u64,
        withdrawn: bool,
    ) -> Result<SignedEntry> {
        if now < snapshot.now {
            return Err(Error::Clock);
        }
        if snapshot.community != self.community {
            return Err(Error::Authority);
        }
        let g = snapshot.groups.get(group).ok_or(Error::Invalid)?;
        if !g.members.contains(&self.me) || (g.level == Level::Public) == withdrawn {
            return Err(Error::Authority);
        }
        let (revision, name, description) = (g.revision, g.name.as_str(), g.description.as_str());
        if !withdrawn && name.trim().is_empty() {
            return Err(Error::Invalid);
        }
        let held = self.held.get_mut(group).ok_or(Error::Authority)?;
        let window = (now / LISTING_WINDOW).max(held.floor_window);
        let counter = (u64::from(u32::try_from(window).map_err(|_| Error::Clock)?) << 32)
            | u64::from(u32::try_from(revision).unwrap_or(u32::MAX));
        let digest = *ckmg::hash(&encode(&(withdrawn, name, description))?).value();
        if let Some((last, last_digest)) = &held.last
            && (counter < *last || (counter == *last && digest != *last_digest))
        {
            return Err(Error::Conflict);
        }
        let key = SigningKey::from_bytes(&held.secret);
        let entry = Entry {
            key: key.verifying_key().to_bytes(),
            name: name.into(),
            description: description.into(),
            counter,
            expires_ms: window
                .saturating_add(2)
                .saturating_mul(LISTING_WINDOW)
                .saturating_mul(1_000),
            withdrawn,
        };
        let signed = SignedEntry::sign(entry, &key).map_err(|_| Error::Invalid)?;
        held.last = Some((counter, digest));
        Ok(signed)
    }

    /// Whether the key must be rotated now: a departure or fork happened after
    /// the key was created and the next window boundary has passed.
    pub fn rotation_due(&self, snapshot: &Snapshot, group: &Id, now: u64) -> bool {
        let Some(held) = self.held.get(group) else {
            return false;
        };
        let trigger = self.churn(snapshot, group).max(held.fork_seen);
        trigger > held.handled && now >= (trigger / LISTING_WINDOW + 1) * LISTING_WINDOW
    }

    /// Replace the key of a public room: sign a tombstone with the old key and
    /// create the next generation. The caller sends `share` to the other
    /// members, publishes the tombstone under the old room and requests passes
    /// under the new room id. Batching comes from [`Listings::rotation_due`].
    pub fn rotate(&mut self, snapshot: &Snapshot, group: &Id, now: u64) -> Result<Rotation> {
        if !self.rotation_due(snapshot, group, now) {
            return Err(Error::Conflict);
        }
        let g = self.public_member_group(snapshot, group)?;
        let (revision, name, description) = (g.revision, g.name.clone(), g.description.clone());
        let churn = self.churn(snapshot, group);
        let old = self.held.get(group).ok_or(Error::Authority)?;
        let window = (now / LISTING_WINDOW).max(old.floor_window) + 1;
        let counter = (u64::from(u32::try_from(window).map_err(|_| Error::Clock)?) << 32)
            | u64::from(u32::try_from(revision).unwrap_or(u32::MAX));
        let key = SigningKey::from_bytes(&old.secret);
        let tombstone = SignedEntry::sign(
            Entry {
                key: key.verifying_key().to_bytes(),
                name,
                description,
                counter,
                expires_ms: (window + 2)
                    .saturating_mul(LISTING_WINDOW)
                    .saturating_mul(1_000),
                withdrawn: true,
            },
            &key,
        )
        .map_err(|_| Error::Invalid)?;
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|_| Error::Unavailable)?;
        let next = Held {
            secret,
            floor_window: 0,
            generation: old.generation.saturating_add(1),
            handled: churn.max(old.fork_seen),
            fork_seen: 0,
            last: None,
        };
        secret.zeroize();
        let share = ListingShare {
            community: self.community.clone(),
            group: *group,
            secret: next.secret,
            floor_window: 0,
            generation: next.generation,
            handled: next.handled,
        };
        let room = cmbl::listing::room_id(&next.public());
        self.held.insert(*group, next);
        Ok(Rotation {
            tombstone,
            share,
            room,
        })
    }

    /// Forget the key of a group, for example after its tombstone was accepted
    /// or when the owner left. The forum entry then lapses on its own.
    pub fn retire(&mut self, group: &Id) {
        self.held.remove(group);
    }

    /// Drop keys of groups this device's owner no longer belongs to.
    pub fn prune(&mut self, snapshot: &Snapshot) {
        let me = &self.me;
        self.held.retain(|id, _| {
            snapshot
                .groups
                .get(id)
                .is_some_and(|g| g.members.contains(me))
        });
    }

    /// Decide which fork of a public room keeps the listing. Until `wait`
    /// seconds after `forked_at` the parent keeps it; afterwards the fork with
    /// more members does, and a tie goes to the older parent. When the child
    /// wins, the key moves to it on this device (and is dropped if the owner did
    /// not follow the child); the parent, if still public, then needs a key of
    /// its own via [`Listings::create`]. `forked_at` is the fork's effective
    /// time is recorded in the snapshot. Every fork also schedules a rotation.
    pub fn fork(
        &mut self,
        snapshot: &Snapshot,
        (parent, child): (&Id, &Id),
        wait: u64,
        now: u64,
    ) -> Result<Keeper> {
        let p = snapshot.groups.get(parent).ok_or(Error::Invalid)?;
        let c = snapshot.groups.get(child).ok_or(Error::Invalid)?;
        let decided = c.created_at.saturating_add(wait);
        if let Some(held) = self.held.get_mut(parent) {
            held.fork_seen = held.fork_seen.max(c.created_at);
        }
        if now < decided || c.members.len() <= p.members.len() {
            return Ok(Keeper::Parent);
        }
        if let Some(mut held) = self.held.remove(parent)
            && c.members.contains(&self.me)
        {
            held.floor_window = held.floor_window.max(decided / LISTING_WINDOW + 1);
            self.held.insert(*child, held);
        }
        Ok(Keeper::Child)
    }
}
