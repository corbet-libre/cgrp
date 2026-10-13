use crate::{Band, DAY, Error, Id, Policy, PolicySource, Result, encode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Level {
    Circle,
    Ingroup,
    Opening,
    Public,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum ForkKind {
    Add,
    Exclusion { target: String },
    Split,
    Merge,
    Open,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Command {
    Create {
        id: Id,
        members: BTreeSet<String>,
        seed: bool,
    },
    Fork {
        id: Id,
        parents: Vec<Id>,
        members: BTreeSet<String>,
        kind: ForkKind,
    },
    Join {
        group: Id,
        member: String,
        vouches: BTreeSet<String>,
    },
    Leave {
        group: Id,
    },
    /// Set the public name and description shown in the forum listing. Any
    /// member may propose; the ordered result is what the listing key signs.
    Describe {
        group: Id,
        name: String,
        description: String,
    },
    Tick,
}

/// Exact statement signed by a currently authorized community device. Signature
/// verification and current Guard/Contacts authority belong to the trusted port.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Consent {
    pub community: String,
    pub member: String,
    pub operation: Id,
    pub policy_epoch: u64,
    pub command_digest: Id,
    pub profile_visibility: bool,
    pub valid_until: u64,
    /// The consenting member's fresh MLS key package for the group this
    /// command creates (empty for every other command). It is covered by the
    /// signature, so nobody can swap in a package the member did not make.
    #[serde(default)]
    pub key_package: Vec<u8>,
    /// The consenting member's OWN lineage-read handle: a locator only. Every
    /// verifier reads the member's lineage through it and believes nothing but
    /// the Charter-verified record bound to `member`. Covered by the signature,
    /// so nobody can swap it on the way; empty when the consent needs no read.
    #[serde(default)]
    pub lineage_handle: Vec<u8>,
    pub signature: Vec<u8>,
    pub authority: Vec<u8>,
}

impl Consent {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        encode(&(
            "cgrp.consent.v4",
            &self.community,
            &self.member,
            self.operation,
            self.policy_epoch,
            self.command_digest,
            self.profile_visibility,
            self.valid_until,
            &self.key_package,
            &self.lineage_handle,
        ))
    }
}

pub trait Authority {
    /// Must verify Guard, exact statement signature, current revocations/device
    /// authority and scope. No raw public key may become membership authority.
    fn consent(&self, consent: &Consent, now: u64) -> Result<()>;
    fn contact(&self, community: &str, member: &str, contact: &str, now: u64) -> Result<()>;
    fn seed(&self, community: &str, group: &Id, now: u64) -> Result<()>;
    /// Authenticate this exact missing parent under the selected current Policy
    /// for the current local recipient
    /// and original operation. Decoded metadata alone never grants authority.
    /// The trusted adapter must refresh the original invitation and maintained
    /// MLS evidence at each call; private peer Lineage is not inferred here.
    fn parent(&self, _: &crate::GroupState, _: &Request, _: &Policy, _: u64) -> Result<()> {
        Err(Error::Unavailable)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub operation: Id,
    /// Canonical sorted commitments to the exact authenticated parent groups.
    /// A newcomer requires original MLS/invitation import before preparation.
    pub parents: Vec<crate::ParentRef>,
    /// Signed command time, shared by all participants. Publication rechecks
    /// current authority; waiting never moves opening or cooldown timestamps.
    pub effective_at: u64,
    pub actor: String,
    pub command: Command,
    pub consents: Vec<Consent>,
}

impl Request {
    pub fn command_digest(&self) -> Result<Id> {
        Ok(*ckmg::hash(&encode(&(
            "cgrp.command.v2",
            &self.actor,
            &self.command,
            &self.parents,
            self.effective_at,
        ))?)
        .value())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Group {
    pub(crate) revision: u64,
    pub(crate) policy_epoch: u64,
    pub(crate) changed_at: u64,
    pub(crate) id: Id,
    pub(crate) lineage: Id,
    pub(crate) parents: Vec<Id>,
    pub(crate) level: Level,
    pub(crate) members: BTreeSet<String>,
    pub(crate) seed: bool,
    pub(crate) opened: Option<u64>,
    pub(crate) band: usize,
    pub(crate) joins: Vec<u64>,
    /// Effective time of the command that created this group or fork.
    pub(crate) created_at: u64,
    /// Effective time of the latest departure from this group.
    pub(crate) churn_at: u64,
    pub(crate) name: String,
    pub(crate) description: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Snapshot {
    pub(crate) community: String,
    pub(crate) revision: u64,
    pub(crate) policy_epoch: u64,
    pub(crate) now: u64,
    pub(crate) groups: BTreeMap<Id, Group>,
    pub(crate) exclusions: BTreeMap<String, (u64, BTreeMap<String, u64>)>,
    pub(crate) last: Option<(Id, Id)>,
}

impl Snapshot {
    /// Read only the canonical Groups checkpoint from the original encrypted
    /// Store. A missing initial record is empty; corrupt or foreign state fails.
    /// This is a local view, not a membership or consent capability.
    pub fn load<B: cwst::backend::Backend>(
        community: &str,
        store: &cwst::Store<B>,
    ) -> Result<Self> {
        if !store.is_scope(community) {
            return Err(Error::Authority);
        }
        let snapshot = match store
            .read("cgrp", b"snapshot.v1")
            .map_err(|_| Error::Reconcile)?
        {
            Some(bytes) => postcard::from_bytes::<Self>(bytes).map_err(|_| Error::Invalid)?,
            None => Self::empty(community.into()),
        };
        if snapshot.community != community {
            return Err(Error::Authority);
        }
        Ok(snapshot)
    }

    /// Store owner and key under which [`Self::load`] reads the checkpoint.
    pub const STORE_OWNER: &'static str = "cgrp";
    pub const STORE_KEY: &'static [u8] = b"snapshot.v1";

    /// The canonical checkpoint bytes `load` accepts. Writing them is the
    /// adapter's one version-fenced Store commit; this grants no authority.
    pub fn checkpoint_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::Invalid)
    }

    pub fn empty(community: String) -> Self {
        Self {
            community,
            revision: 0,
            policy_epoch: 0,
            now: 0,
            groups: BTreeMap::new(),
            exclusions: BTreeMap::new(),
            last: None,
        }
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn community(&self) -> &str {
        &self.community
    }
    pub fn members(&self, group: &Id) -> Result<&BTreeSet<String>> {
        self.groups
            .get(group)
            .map(|g| &g.members)
            .ok_or(Error::Invalid)
    }
    /// Identifiers of every group in this local view, in canonical order.
    /// Together with `members` this is the explicit, read-only membership
    /// interface that Threads and Board consume; it grants no authority.
    pub fn ids(&self) -> impl Iterator<Item = &Id> {
        self.groups.keys()
    }
    /// One display view per group under the supplied current policy.
    pub fn views(&self, policy: &Policy, now: u64) -> Result<Vec<GroupView>> {
        self.groups
            .keys()
            .map(|id| view(self, id, policy, now))
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commit {
    Applied,
    Conflict,
    Unknown,
}

/// Adapter to the encrypted device checkpoint/outbox transaction (cwst). It must
/// compare the expected revision and persist the entire candidate atomically.
/// Unknown outcomes require a fresh read, never publication or blind mutation.
pub type CommitFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Commit>> + 'a>>;
pub trait Persistence {
    fn commit<'a>(
        &'a mut self,
        expected: u64,
        candidate: &'a Snapshot,
        effects: &'a [Effect],
    ) -> CommitFuture<'a>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Effect {
    Membership {
        group: Id,
        lineage: Id,
        parents: Vec<Id>,
        members: BTreeSet<String>,
        level: Level,
        policy_epoch: u64,
        revision: u64,
    },
    WithdrawListing {
        group: Id,
    },
    ConsentLapsed {
        group: Id,
    },
}

/// A published effect cannot be constructed or deserialized by a frontend.
/// Threads must consume this capability, checking scope/revision exactly once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedEffect {
    community: String,
    event: Effect,
}

impl CommittedEffect {
    pub fn community(&self) -> &str {
        &self.community
    }
    pub fn event(&self) -> &Effect {
        &self.event
    }
}

/// Verified preparation input for Threads. This only permits preparing its
/// candidate; publication still requires the shared durable transaction.
pub struct PreparedEffect<'a> {
    community: &'a str,
    event: &'a Effect,
    band: &'a Band,
    valid_until: u64,
    consent_valid_until: u64,
    state: crate::GroupState,
}

impl PreparedEffect<'_> {
    pub fn group_state(&self) -> &crate::GroupState {
        &self.state
    }
    /// Earliest policy or signed-consent expiry; preparation confers no lease.
    pub fn valid_until(&self) -> u64 {
        self.valid_until.min(self.consent_valid_until)
    }
    /// Exact verified curve row selected for this effect and candidate revision.
    pub fn policy_band(&self) -> &Band {
        self.band
    }
    /// Expiry of the authenticated policy that prepared this candidate.
    pub fn policy_valid_until(&self) -> u64 {
        self.valid_until
    }
    pub fn community(&self) -> &str {
        self.community
    }
    pub fn event(&self) -> &Effect {
        self.event
    }
}

pub struct Candidate {
    expected: u64,
    base: Snapshot,
    request: Request,
    max_groups: usize,
    snapshot: Snapshot,
    effects: Vec<Effect>,
    policy: Policy,
    consent_valid_until: u64,
    transition_valid_until: u64,
    imported_parents: Vec<crate::GroupState>,
}

mod parents;
pub use parents::prepare_with_parents;

impl Candidate {
    /// Require the exact predecessor loaded from authenticated owner storage,
    /// not merely its numeric revision. A deserialized alternate snapshot with
    /// the same revision cannot replace membership, lineage or replay state.
    pub fn check_base(&self, current: &Snapshot) -> Result<()> {
        if &self.base != current {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    /// Repeat the original consent, contact, seed and signed-policy checks at
    /// publication time, after asynchronous custody work. Preparation is not a
    /// lease: revocation or a changed policy refuses the whole candidate.
    /// Original command times remain fixed, so waiting cannot reset an opening
    /// deadline, cooldown or join timestamp. Crossing a timed privacy transition
    /// requires a fresh preparation instead of publishing the old state.
    pub fn revalidate(
        &self,
        source: &impl PolicySource,
        authority: &impl Authority,
        now: u64,
    ) -> Result<()> {
        self.check_time(now)?;
        let fresh = parents::prepare_at_with_parents(
            &self.base,
            &self.request,
            &self.imported_parents,
            source,
            authority,
            (self.snapshot.now, now),
            self.max_groups,
        )?;
        if fresh.snapshot != self.snapshot
            || fresh.effects != self.effects
            || fresh.policy != self.policy
        {
            return Err(Error::Authority);
        }
        Ok(())
    }

    fn check_time(&self, now: u64) -> Result<()> {
        if now < self.snapshot.now {
            return Err(Error::Clock);
        }
        if now
            >= self
                .policy
                .valid_until
                .min(self.consent_valid_until)
                .min(self.transition_valid_until)
        {
            return Err(Error::Authority);
        }
        Ok(())
    }

    pub fn prepare_effects(&self) -> Vec<PreparedEffect<'_>> {
        self.effects
            .iter()
            .map(|event| {
                let group = match event {
                    Effect::Membership { group, .. }
                    | Effect::WithdrawListing { group }
                    | Effect::ConsentLapsed { group } => group,
                };
                // Every effect is produced from an extant group; prepare has
                // validated every group's band against this exact Policy.
                let band = &self.policy.bands[self.snapshot.groups[group].band];
                PreparedEffect {
                    state: crate::GroupState::new(
                        &self.snapshot.community,
                        &self.snapshot.groups[group],
                    ),
                    community: &self.snapshot.community,
                    event,
                    band,
                    valid_until: self.policy.valid_until,
                    consent_valid_until: self.consent_valid_until.min(self.transition_valid_until),
                }
            })
            .collect()
    }

    /// Effects become visible only after the owning durable transaction commits.
    pub async fn persist(
        self,
        store: &mut dyn Persistence,
        now: u64,
    ) -> Result<(Snapshot, Vec<CommittedEffect>)> {
        self.check_time(now)?;
        match store
            .commit(self.expected, &self.snapshot, &self.effects)
            .await?
        {
            Commit::Applied => {
                let effects = self
                    .effects
                    .into_iter()
                    .map(|event| CommittedEffect {
                        community: self.snapshot.community.clone(),
                        event,
                    })
                    .collect();
                Ok((self.snapshot, effects))
            }
            Commit::Conflict => Err(Error::Conflict),
            Commit::Unknown => Err(Error::Reconcile),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub enum NextChange {
    ConsentIngroup,
    ConsentPublic,
    OpeningDeadline(u64),
    PrivateIngroup,
    PrivateCircle,
    Seed,
}

#[derive(Clone, Debug, PartialEq, Serialize, schemars::JsonSchema)]
pub struct GroupView {
    pub id: Id,
    pub lineage: Id,
    pub level: Level,
    pub size: u16,
    pub cap: u16,
    pub next_at: u16,
    pub next: NextChange,
    pub curve_row: Band,
    pub seat_weight_now: f64,
}

pub fn view(state: &Snapshot, group: &Id, policy: &Policy, now: u64) -> Result<GroupView> {
    policy.validate(now)?;
    let g = state.groups.get(group).ok_or(Error::Invalid)?;
    let (next_at, next) = if g.seed {
        (policy.cap, NextChange::Seed)
    } else {
        match g.level {
            Level::Circle => (13, NextChange::ConsentIngroup),
            Level::Ingroup => (43, NextChange::ConsentPublic),
            Level::Opening => (
                43,
                NextChange::OpeningDeadline(
                    g.opened
                        .ok_or(Error::Invalid)?
                        .saturating_add(policy.open_seconds),
                ),
            ),
            Level::Public => (36, NextChange::PrivateIngroup),
        }
    };
    let size = g.members.len() as u16;
    Ok(GroupView {
        id: g.id,
        lineage: g.lineage,
        level: g.level,
        size,
        cap: policy.cap,
        next_at,
        next,
        curve_row: policy.bands.get(g.band).ok_or(Error::Invalid)?.clone(),
        seat_weight_now: policy.seat_weight(size),
    })
}

/// Pure preparation. The caller supplies time and resource bounds; no clocks,
/// network or filesystem are reached implicitly.
pub fn prepare(
    state: &Snapshot,
    request: &Request,
    source: &impl PolicySource,
    authority: &impl Authority,
    now: u64,
    max_groups: usize,
) -> Result<Candidate> {
    prepare_at(state, request, source, authority, (now, now), max_groups)
}

fn prepare_at(
    state: &Snapshot,
    request: &Request,
    source: &impl PolicySource,
    authority: &impl Authority,
    (now, authorized_at): (u64, u64),
    max_groups: usize,
) -> Result<Candidate> {
    if now < state.now {
        return Err(Error::Clock);
    }
    if request.effective_at > now {
        return Err(Error::Clock);
    }
    if request.parents != state.parent_references(&request.command)? {
        return Err(Error::Conflict);
    }
    if request.parents.iter().any(|parent| {
        state
            .groups
            .get(&parent.id)
            .is_some_and(|group| group.changed_at > request.effective_at)
    }) {
        return Err(Error::Clock);
    }
    let policy = source.current(&state.community, authorized_at)?;
    policy.validate(authorized_at)?;
    if policy.epoch < state.policy_epoch {
        return Err(Error::Policy);
    }
    let digest = request.command_digest()?;
    if state
        .last
        .as_ref()
        .is_some_and(|(op, _)| *op == request.operation)
    {
        return Err(Error::Conflict);
    }
    if request.actor.is_empty()
        || request.actor.len() > 200
        || request.consents.len() > usize::from(policy.cap)
    {
        return Err(Error::Invalid);
    }
    let mut verified = BTreeSet::new();
    for c in &request.consents {
        if c.community != state.community
            || c.operation != request.operation
            || c.policy_epoch != policy.epoch
            || c.command_digest != digest
            || c.valid_until <= authorized_at
            || c.member.is_empty()
            || c.member.len() > 200
            || !verified.insert(c.member.clone())
        {
            return Err(Error::Authority);
        }
        authority.consent(c, authorized_at)?;
    }
    if !matches!(request.command, Command::Tick) && !verified.contains(&request.actor) {
        return Err(Error::Authority);
    }
    let mut next = state.clone();
    next.now = now;
    next.policy_epoch = policy.epoch;
    next.revision = state.revision.checked_add(1).ok_or(Error::Capacity)?;
    next.last = Some((request.operation, digest));
    let mut effects = Vec::new();
    let effective_at = request.effective_at;
    let affected: BTreeSet<Id> = match &request.command {
        Command::Create { id, .. } | Command::Fork { id, .. } => BTreeSet::from([*id]),
        Command::Join { group, .. }
        | Command::Leave { group }
        | Command::Describe { group, .. } => BTreeSet::from([*group]),
        Command::Tick => next.groups.keys().copied().collect(),
    };
    // A peer command changes its own group only. Unrelated local groups and
    // nonmover parents must not become part of another device's transcript.
    // Tick owns local timed transitions; joins first apply their own deadline.
    for g in next
        .groups
        .values_mut()
        .filter(|g| affected.contains(&g.id))
    {
        shrink(g, &policy, effective_at, &mut effects);
    }
    match &request.command {
        Command::Create { id, members, seed } => {
            validate_new(
                &next,
                id,
                members,
                &verified,
                &request.actor,
                max_groups,
                &policy,
            )?;
            if *seed {
                authority.seed(&state.community, id, authorized_at)?;
                visibility(request, members)?;
            } else {
                if members.len() > usize::from(policy.circle_max) {
                    return Err(Error::Invalid);
                }
                for member in members.iter().filter(|m| **m != request.actor) {
                    authority.contact(&state.community, &request.actor, member, authorized_at)?;
                }
            }
            next.groups.insert(
                *id,
                Group {
                    revision: 0,
                    policy_epoch: policy.epoch,
                    changed_at: effective_at,
                    id: *id,
                    lineage: *id,
                    parents: vec![],
                    level: if *seed { Level::Public } else { Level::Circle },
                    members: members.clone(),
                    seed: *seed,
                    opened: None,
                    band: 0,
                    joins: vec![],
                    created_at: effective_at,
                    churn_at: 0,
                    name: String::new(),
                    description: String::new(),
                },
            );
        }
        Command::Fork {
            id,
            parents,
            members,
            kind,
        } => {
            validate_new(
                &next,
                id,
                members,
                &verified,
                &request.actor,
                max_groups,
                &policy,
            )?;
            if parents.is_empty()
                || parents.len() > 2
                || parents.iter().collect::<BTreeSet<_>>().len() != parents.len()
            {
                return Err(Error::Invalid);
            }
            let parent = next.groups.get(&parents[0]).ok_or(Error::Invalid)?.clone();
            let mut union = BTreeSet::new();
            for p in parents {
                let g = next.groups.get(p).ok_or(Error::Invalid)?;
                if !g.members.contains(&request.actor) {
                    return Err(Error::Authority);
                }
                union.extend(g.members.iter().cloned());
            }
            if matches!(kind, ForkKind::Merge) != (parents.len() == 2) {
                return Err(Error::Invalid);
            }
            let mut level = parent.level;
            let mut opened = parent.opened;
            match kind {
                ForkKind::Add => {
                    if members.difference(&union).count() == 0 {
                        return Err(Error::Invalid);
                    }
                    for newcomer in members.difference(&union) {
                        authority.contact(
                            &state.community,
                            &request.actor,
                            newcomer,
                            authorized_at,
                        )?;
                    }
                    if members.len() > usize::from(policy.circle_max)
                        && parent.level == Level::Circle
                    {
                        level = Level::Ingroup;
                    }
                    if members.len() > usize::from(policy.ingroup_max) && level != Level::Public {
                        return Err(Error::Invalid);
                    }
                }
                ForkKind::Exclusion { target } => {
                    if !union.contains(target)
                        || members.contains(target)
                        || !members.is_subset(&union)
                    {
                        return Err(Error::Invalid);
                    }
                    let entry = next
                        .exclusions
                        .entry(request.actor.clone())
                        .or_insert((0, BTreeMap::new()));
                    if (!entry.1.is_empty()
                        && effective_at < entry.0.saturating_add(policy.fork_cooldown))
                        || entry.1.get(target).is_some_and(|last| {
                            effective_at < last.saturating_add(policy.retarget_cooldown)
                        })
                    {
                        return Err(Error::Conflict);
                    }
                    entry.0 = effective_at;
                    entry.1.insert(target.clone(), effective_at);
                }
                ForkKind::Split => {
                    if !members.is_subset(&union) {
                        return Err(Error::Invalid);
                    }
                }
                ForkKind::Merge => {
                    if !members.is_subset(&union) || union.len() > usize::from(policy.circle_max) {
                        return Err(Error::Invalid);
                    }
                    level = Level::Circle;
                }
                ForkKind::Open => {
                    if parent.level != Level::Ingroup || !members.is_subset(&union) {
                        return Err(Error::Invalid);
                    }
                    visibility(request, members)?;
                    level = Level::Opening;
                    opened = Some(effective_at);
                }
            }
            if level == Level::Opening {
                visibility(request, members)?;
            }
            if level == Level::Public {
                if members.len() < usize::from(policy.split_public_min) {
                    level = Level::Ingroup;
                } else {
                    visibility(request, members)?;
                }
            }
            if level == Level::Ingroup && members.len() <= usize::from(policy.shrink_ingroup) {
                level = Level::Circle;
            }
            if level != Level::Opening {
                opened = None;
            }
            next.groups.insert(
                *id,
                Group {
                    revision: 0,
                    policy_epoch: policy.epoch,
                    changed_at: effective_at,
                    id: *id,
                    lineage: parent.lineage,
                    parents: parents.clone(),
                    level,
                    members: members.clone(),
                    seed: false,
                    opened,
                    band: 0,
                    joins: vec![],
                    created_at: effective_at,
                    churn_at: 0,
                    name: parent.name.clone(),
                    description: parent.description.clone(),
                },
            );
        }
        Command::Join {
            group,
            member,
            vouches,
        } => {
            let g = next.groups.get_mut(group).ok_or(Error::Invalid)?;
            if member != &request.actor {
                return Err(Error::Authority);
            }
            if g.members.contains(member) {
                return Err(Error::Conflict);
            }
            if g.members.len() >= usize::from(policy.cap) {
                return Err(Error::Capacity);
            }
            if g.level == Level::Circle
                || (g.level == Level::Ingroup && g.members.len() >= usize::from(policy.ingroup_max))
            {
                return Err(Error::Invalid);
            }
            if matches!(g.level, Level::Opening | Level::Public) {
                visibility(request, &BTreeSet::from([member.clone()]))?;
            }
            if g.level == Level::Ingroup {
                let required = policy.bands[g.band].vouches;
                if vouches.len() < usize::from(required) {
                    return Err(Error::Authority);
                }
                for v in vouches {
                    if !g.members.contains(v) || !verified.contains(v) {
                        return Err(Error::Authority);
                    }
                    authority.contact(&state.community, v, member, authorized_at)?;
                }
            }
            g.joins
                .retain(|at| effective_at.saturating_sub(*at) < 3_600);
            if let Some(limit) = policy.bands[g.band].joins_per_hour
                && g.joins.len() >= usize::from(limit)
            {
                return Err(Error::Capacity);
            }
            g.members.insert(member.clone());
            g.joins.push(effective_at);
            if g.level == Level::Opening && g.members.len() > usize::from(policy.ingroup_max) {
                g.level = Level::Public;
                g.opened = None;
            }
        }
        Command::Leave { group } => {
            let g = next.groups.get_mut(group).ok_or(Error::Invalid)?;
            if !g.members.remove(&request.actor) {
                return Err(Error::Authority);
            }
            g.churn_at = effective_at;
            shrink(g, &policy, effective_at, &mut effects);
        }
        Command::Describe {
            group,
            name,
            description,
        } => {
            let g = next.groups.get_mut(group).ok_or(Error::Invalid)?;
            if !g.members.contains(&request.actor) {
                return Err(Error::Authority);
            }
            if !valid_listing_text(name, description) {
                return Err(Error::Invalid);
            }
            g.name = name.clone();
            g.description = description.clone();
        }
        Command::Tick => {}
    }
    for (id, group) in &mut next.groups {
        if !affected.contains(id) {
            continue;
        }
        group.band = policy.band(group.members.len() as u16, group.band)?;
        group.policy_epoch = policy.epoch;
        if state.groups.get(id) != Some(group) {
            group.changed_at = effective_at;
            group.revision = group.revision.checked_add(1).ok_or(Error::Capacity)?;
            effects.push(Effect::Membership {
                group: *id,
                lineage: group.lineage,
                parents: group.parents.clone(),
                members: group.members.clone(),
                level: group.level,
                policy_epoch: policy.epoch,
                revision: group.revision,
            });
        }
    }
    Ok(Candidate {
        expected: state.revision,
        base: state.clone(),
        request: request.clone(),
        max_groups,
        transition_valid_until: next
            .groups
            .values()
            .filter(|group| group.level == Level::Opening)
            .filter_map(|group| group.opened)
            .map(|opened| opened.saturating_add(policy.open_seconds))
            .min()
            .unwrap_or(policy.valid_until),
        snapshot: next,
        effects,
        consent_valid_until: request
            .consents
            .iter()
            .map(|c| c.valid_until)
            .min()
            .unwrap_or(policy.valid_until),
        policy,
        imported_parents: vec![],
    })
}

/// Bounds shared with the forum's listing entry (64 and 512 bytes, no control characters).
pub(crate) fn valid_listing_text(name: &str, description: &str) -> bool {
    name.len() <= 64
        && description.len() <= 512
        && !name
            .chars()
            .chain(description.chars())
            .any(char::is_control)
}

fn validate_new(
    state: &Snapshot,
    id: &Id,
    members: &BTreeSet<String>,
    verified: &BTreeSet<String>,
    actor: &str,
    max: usize,
    policy: &Policy,
) -> Result<()> {
    if state.groups.contains_key(id) {
        return Err(Error::Conflict);
    }
    if state.groups.len() >= max || members.len() > usize::from(policy.cap) {
        return Err(Error::Capacity);
    }
    if members.len() < 3 || !members.contains(actor) {
        return Err(Error::Invalid);
    }
    if !members.is_subset(verified) {
        return Err(Error::Authority);
    }
    Ok(())
}

fn visibility(request: &Request, members: &BTreeSet<String>) -> Result<()> {
    if members.iter().any(|m| {
        !request
            .consents
            .iter()
            .any(|c| &c.member == m && c.profile_visibility)
    }) {
        return Err(Error::Authority);
    }
    Ok(())
}

fn shrink(g: &mut Group, p: &Policy, now: u64, effects: &mut Vec<Effect>) {
    if g.seed {
        return;
    }
    if g.level == Level::Opening
        && g.opened
            .is_some_and(|at| now.saturating_sub(at) >= p.open_seconds)
    {
        g.level = Level::Ingroup;
        g.opened = None;
        effects.push(Effect::ConsentLapsed { group: g.id });
        effects.push(Effect::WithdrawListing { group: g.id });
    }
    if g.level == Level::Public && g.members.len() <= usize::from(p.shrink_public) {
        g.level = Level::Ingroup;
        effects.push(Effect::WithdrawListing { group: g.id });
    }
    if g.level == Level::Ingroup && g.members.len() <= usize::from(p.shrink_ingroup) {
        g.level = Level::Circle;
    }
}

/// Formats only; no seat spending or forced leave is enabled by this crate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SeatSpend {
    pub epoch: u64,
    pub amount: f64,
    pub receipts_proof: Vec<u8>,
}

/// Bounded rolling history selection; cryptographic disclosure belongs to Threads.
pub fn history_allowed(joined_at: u64, message_at: u64, band: &Band) -> bool {
    band.history_seconds != 0
        && message_at <= joined_at
        && joined_at.saturating_sub(message_at) <= band.history_seconds.min(14 * DAY)
}

#[cfg(test)]
mod consent_tests {
    use super::*;

    fn consent(package: &[u8]) -> Consent {
        Consent {
            community: "alpha".into(),
            member: "m".repeat(96),
            operation: [1; 32],
            policy_epoch: 1,
            command_digest: [2; 32],
            profile_visibility: false,
            valid_until: 10,
            key_package: package.to_vec(),
            lineage_handle: vec![],
            signature: vec![],
            authority: vec![],
        }
    }

    #[test]
    fn the_lineage_handle_is_covered_by_the_signed_statement() {
        let plain = consent(b"").signing_bytes().unwrap();
        let mut with_handle = consent(b"");
        with_handle.lineage_handle = b"handle".to_vec();
        assert_ne!(plain, with_handle.signing_bytes().unwrap());
    }

    #[test]
    fn the_key_package_is_covered_by_the_signed_statement() {
        let plain = consent(b"").signing_bytes().unwrap();
        let with_package = consent(b"package").signing_bytes().unwrap();
        let swapped = consent(b"other").signing_bytes().unwrap();
        assert_ne!(plain, with_package);
        assert_ne!(with_package, swapped);
        assert_eq!(with_package, consent(b"package").signing_bytes().unwrap());
    }
}
