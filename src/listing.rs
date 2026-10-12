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
//! Counters are derived, never chosen: `window << 32 | group revision`, where
//! `window` counts [`LISTING_WINDOW`] spans of wall time. Every member who signs
//! in the same window therefore produces the identical entry (ed25519 is
//! deterministic), so concurrent re-publication never conflicts at the forum,
//! while every ordered group change or new window yields a strictly newer entry.
use crate::{DAY, Error, Id, Level, Result, Snapshot, encode};
use cmbl::listing::{DESCRIPTION_BYTES, Entry, NAME_BYTES, SignedEntry};
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
    fn public_member(&self, snapshot: &Snapshot, group: &Id) -> Result<u64> {
        if snapshot.community != self.community {
            return Err(Error::Authority);
        }
        let g = snapshot.groups.get(group).ok_or(Error::Invalid)?;
        if g.level != Level::Public || !g.members.contains(&self.me) {
            return Err(Error::Authority);
        }
        Ok(g.revision)
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
            last: None,
        };
        secret.zeroize();
        let public = held.public();
        self.held.insert(*group, held);
        Ok(public)
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
        })
    }

    /// Accept a key received from a fellow member. If two members created a key
    /// at the same time, the numerically lowest public key wins on every device.
    pub fn adopt(&mut self, snapshot: &Snapshot, share: &ListingShare) -> Result<()> {
        if share.community != self.community {
            return Err(Error::Authority);
        }
        self.public_member(snapshot, &share.group)?;
        let incoming = Held {
            secret: share.secret,
            floor_window: share.floor_window,
            last: None,
        };
        if let Some(current) = self.held.get(&share.group)
            && current.public() <= incoming.public()
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
        name: &str,
        description: &str,
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
        let revision = g.revision;
        if name.len() > NAME_BYTES || description.len() > DESCRIPTION_BYTES {
            return Err(Error::Capacity);
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
    /// time as recorded by the caller; the snapshot does not keep it.
    pub fn fork(
        &mut self,
        snapshot: &Snapshot,
        (parent, child): (&Id, &Id),
        (forked_at, wait): (u64, u64),
        now: u64,
    ) -> Result<Keeper> {
        let p = snapshot.groups.get(parent).ok_or(Error::Invalid)?;
        let c = snapshot.groups.get(child).ok_or(Error::Invalid)?;
        let decided = forked_at.saturating_add(wait);
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
