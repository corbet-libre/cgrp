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
//! A listing entry is a projection of public state, valid exactly while the
//! room is public by the warm count. Its expiry is the computed moment the
//! warm count would fall below the public exit threshold ([`SHRINK_PUBLIC`], 36
//! with hysteresis) if nobody came: with `N` warm ends sorted ascending,
//! `ends[N-37]`. Equal ends fall out together. There is no TTL and no presence
//! renewal; re-publication is only justified by a new accepted visit or group
//! change, and the entry for a given projection is identical whoever signs it
//! (ed25519 is deterministic), so concurrent re-publication never conflicts at
//! the forum.
//!
//! After any departure or fork the key is rotated immediately as part of that
//! fact: the old head is dead for live entries (only a tombstone withdrawing
//! the superseded room may still be signed with it), so rotation and the head
//! transition are inseparable. A stale share can neither be adopted fresh nor
//! sign against the new head.
//!
//! Counters order entries for the forum's replace rule: the high 32 bits carry
//! the expiry (or the fork-handover floor, which only ever orders), the low 32
//! bits the group revision. A higher counter always replaces a lower one; an
//! equal counter with different bytes is a conflict, never a merge.
use crate::{DAY, Error, Group, Id, Level, Result, Snapshot, encode, warm::SHRINK_PUBLIC};
use cmbl::listing::{Entry, SignedEntry};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroize;

/// Which fork of a public room keeps the listing and its room identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keeper {
    Parent,
    Child,
}

#[derive(Clone, Serialize, Deserialize)]
struct Held {
    secret: [u8; 32],
    /// Lowest counter-high this key may sign; raised when the listing moves to
    /// a fork so the child's counters always exceed the parent's last one.
    /// Orders only: the expiry a device signs stays its own truthful crossing.
    floor_hi: u64,
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
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ListingShare {
    pub community: String,
    pub group: Id,
    secret: [u8; 32],
    floor_hi: u64,
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
            floor_hi: 0,
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

    /// Whether this device holds the listing key of `group`.
    pub fn holds(&self, group: &Id) -> bool {
        self.held.contains_key(group)
    }

    /// The public rooms of this snapshot that this device's owner belongs to:
    /// the ones whose listing this device may create, share and publish.
    pub fn public_groups(&self, snapshot: &Snapshot) -> Vec<Id> {
        if snapshot.community != self.community {
            return vec![];
        }
        snapshot
            .groups
            .iter()
            .filter(|(_, g)| g.level == Level::Public && g.members.contains(&self.me))
            .map(|(id, _)| *id)
            .collect()
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
            floor_hi: held.floor_hi,
            generation: held.generation,
            handled: held.handled,
        })
    }

    /// Accept a key received from a fellow member. The higher rotation
    /// generation wins; between equal generations (two members acting at the
    /// same time) the numerically lowest public key wins on every device. A
    /// share that predates an already observed departure or fork is stale and
    /// is refused: the old head is dead, and only the covering key may sign.
    pub fn adopt(&mut self, snapshot: &Snapshot, share: &ListingShare) -> Result<()> {
        if share.community != self.community {
            return Err(Error::Authority);
        }
        self.public_member(snapshot, &share.group)?;
        let incoming = Held {
            secret: share.secret,
            floor_hi: share.floor_hi,
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
        if incoming.handled < self.churn(snapshot, &share.group) {
            return Err(Error::Conflict);
        }
        self.held.insert(share.group, incoming);
        Ok(())
    }

    /// The computed moment the warm count would fall below the public exit
    /// threshold ([`SHRINK_PUBLIC`]) if nobody came: with the warm ends sorted
    /// ascending, `ends[N-37]`. Equal ends fall out together; the half-open
    /// interval means equality with an end is already expired.
    fn crossing(warm_ends: &[u64]) -> Result<u64> {
        let mut sorted = warm_ends.to_vec();
        sorted.sort_unstable();
        sorted
            .len()
            .checked_sub(SHRINK_PUBLIC as usize + 1)
            .and_then(|at| sorted.get(at).copied())
            .ok_or(Error::Invalid)
    }

    /// Sign the listing entry of a group: a projection of current public state,
    /// valid exactly while the room is public by the warm count. `warm_ends`
    /// carries one warm end (wall-clock seconds) per currently warm seat; the
    /// entry expires at the computed crossing if nobody came. `now` is
    /// wall-clock seconds. Any member holding the key may sign; the entry for a
    /// given projection, group revision, name and description is the same
    /// whoever signs it, so no renewal loop is ever needed. A tombstone
    /// (`withdrawn`) is allowed only once the group is no longer public; it
    /// needs no warm projection, and a stale key may only withdraw, never
    /// extend the superseded head.
    pub fn sign_listing(
        &mut self,
        snapshot: &Snapshot,
        group: &Id,
        now: u64,
        warm_ends: &[u64],
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
        let trigger = self.churn(snapshot, group);
        let held = self.held.get_mut(group).ok_or(Error::Authority)?;
        if !withdrawn && trigger.max(held.fork_seen) > held.handled {
            return Err(Error::Conflict);
        }
        let (counter, expires_ms) = if withdrawn {
            let high = match held.last {
                Some((last, _)) => last.saturating_add(1 << 32),
                None => (u32::try_from(now).map_err(|_| Error::Clock)? as u64) << 32,
            };
            let expires_ms = now
                .checked_mul(1_000)
                .and_then(|ms| ms.checked_add(DAY * 1_000))
                .ok_or(Error::Clock)?;
            (high, expires_ms)
        } else {
            if warm_ends.len() > g.members.len()
                || warm_ends.len() < SHRINK_PUBLIC as usize + 1
                || warm_ends.iter().any(|end| *end <= now)
            {
                return Err(Error::Invalid);
            }
            let crossing = Self::crossing(warm_ends)?;
            let expiry_hi = u32::try_from(crossing).map_err(|_| Error::Clock)? as u64;
            let counter = (expiry_hi.max(held.floor_hi) << 32)
                | u64::from(u32::try_from(revision).unwrap_or(u32::MAX));
            let expires_ms = crossing.saturating_mul(1_000);
            (counter, expires_ms)
        };
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
            expires_ms,
            withdrawn,
        };
        let signed = SignedEntry::sign(entry, &key).map_err(|_| Error::Invalid)?;
        held.last = Some((counter, digest));
        Ok(signed)
    }

    /// Whether the key must be rotated now: a departure or fork happened after
    /// this key last covered one. Rotation is immediate, with no window wait:
    /// it is an inseparable part of the departure/fork fact.
    pub fn rotation_due(&self, snapshot: &Snapshot, group: &Id) -> bool {
        let Some(held) = self.held.get(group) else {
            return false;
        };
        self.churn(snapshot, group).max(held.fork_seen) > held.handled
    }

    /// Replace the key of a public room: sign a tombstone with the old key and
    /// create the next generation. The caller sends `share` to the other
    /// members and publishes the tombstone under the old room. Rotation is due
    /// immediately on any departure or fork, as part of that fact.
    pub fn rotate(&mut self, snapshot: &Snapshot, group: &Id, now: u64) -> Result<Rotation> {
        if !self.rotation_due(snapshot, group) {
            return Err(Error::Conflict);
        }
        let g = self.public_member_group(snapshot, group)?;
        let (revision, name, description) = (g.revision, g.name.clone(), g.description.clone());
        let handled = self
            .churn(snapshot, group)
            .max(self.held.get(group).map(|held| held.fork_seen).unwrap_or(0));
        let old = self.held.get(group).ok_or(Error::Authority)?;
        let counter = match old.last {
            Some((last, _)) => last.saturating_add(1 << 32),
            None => (u32::try_from(now).map_err(|_| Error::Clock)? as u64) << 32,
        };
        let expires_ms = now
            .checked_mul(1_000)
            .and_then(|ms| ms.checked_add(DAY * 1_000))
            .ok_or(Error::Clock)?;
        let counter = counter | u64::from(u32::try_from(revision).unwrap_or(u32::MAX));
        let key = SigningKey::from_bytes(&old.secret);
        let tombstone = SignedEntry::sign(
            Entry {
                key: key.verifying_key().to_bytes(),
                name,
                description,
                counter,
                expires_ms,
                withdrawn: true,
            },
            &key,
        )
        .map_err(|_| Error::Invalid)?;
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|_| Error::Unavailable)?;
        let next = Held {
            secret,
            floor_hi: 0,
            generation: old.generation.saturating_add(1),
            handled,
            fork_seen: 0,
            last: None,
        };
        secret.zeroize();
        let share = ListingShare {
            community: self.community.clone(),
            group: *group,
            secret: next.secret,
            floor_hi: 0,
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
    /// seconds after the fork's effective time (recorded in the snapshot) the
    /// parent keeps it; afterwards the fork with more members does, and a tie
    /// goes to the older parent. When the child wins, the key moves to it on
    /// this device (and is dropped if the owner did not follow the child); the
    /// handover resolves the fork for the moved key, ordering its first
    /// counters above the parent's last while keeping its own truthful expiry.
    /// The parent, if still public, then needs a key of its own via
    /// [`Listings::create`]. Every fork schedules an immediate rotation.
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
            held.floor_hi = held
                .floor_hi
                .max(held.last.map(|(last, _)| last >> 32).unwrap_or(0))
                .saturating_add(1)
                .min(u32::MAX as u64);
            held.handled = held.handled.max(held.fork_seen);
            held.fork_seen = 0;
            self.held.insert(*child, held);
        }
        Ok(Keeper::Child)
    }
}
