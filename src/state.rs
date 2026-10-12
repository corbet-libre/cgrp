//! Canonical per-group metadata. Decoding this value never confers authority.
use crate::{Error, Group, Id, Level, Result, Snapshot, encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Original Groups state authenticated by Threads' MLS GroupContext. Local
/// journal revision, other groups, replay journal and exclusion history are not
/// part of the peer transcript. A decoded value still needs original MLS and
/// independently authenticated invitation/committed-parent verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupState {
    version: u16,
    community: String,
    group: Group,
}

impl GroupState {
    pub(crate) fn new(community: &str, group: &Group) -> Self {
        Self {
            version: 1,
            community: community.into(),
            group: group.clone(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.community.is_empty()
            || self.community.len() > 200
            || self.group.parents.len() > 2
            || self.group.parents.iter().collect::<BTreeSet<_>>().len() != self.group.parents.len()
            || self.group.members.len() > 100
            || self
                .group
                .members
                .iter()
                .any(|m| m.is_empty() || m.len() > 200)
            || self.group.joins.len() > 100
            || !crate::lifecycle::valid_listing_text(&self.group.name, &self.group.description)
            || self.group.band > 8
            || self.group.revision == 0
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    /// Versioned original canonical encoding, bounded before parsing. Canonical
    /// re-encoding also rejects duplicates, unknown fields and alternate forms.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 65_536 {
            return Err(Error::Capacity);
        }
        let state: Self = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if state.canonical_bytes()? != bytes {
            return Err(Error::Invalid);
        }
        Ok(state)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = encode(self)?;
        if bytes.len() > 65_536 {
            return Err(Error::Capacity);
        }
        Ok(bytes)
    }

    pub fn commitment(&self) -> Result<Id> {
        Ok(*ckmg::hash(&encode(&("cgrp.state.v1", self.canonical_bytes()?))?).value())
    }

    pub fn community(&self) -> &str {
        &self.community
    }
    pub fn id(&self) -> &Id {
        &self.group.id
    }
    pub fn revision(&self) -> u64 {
        self.group.revision
    }
    pub fn policy_epoch(&self) -> u64 {
        self.group.policy_epoch
    }
    pub fn level(&self) -> Level {
        self.group.level
    }
    pub fn members(&self) -> &BTreeSet<String> {
        &self.group.members
    }

    pub(crate) fn imported_group(&self) -> Result<Group> {
        self.validate()?;
        Ok(self.group.clone())
    }
}

impl Snapshot {
    /// Exact per-group predecessors for a peer request. This intentionally omits
    /// this device's journal revision and all unrelated local groups.
    pub fn parent_references(&self, command: &crate::Command) -> Result<Vec<ParentRef>> {
        let mut ids = match command {
            crate::Command::Create { .. } | crate::Command::Tick => vec![],
            crate::Command::Fork { parents, .. } => parents.clone(),
            crate::Command::Join { group, .. }
            | crate::Command::Leave { group }
            | crate::Command::Describe { group, .. } => vec![*group],
        };
        ids.sort();
        if ids.len() > 2 || ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::Invalid);
        }
        ids.into_iter()
            .map(|id| {
                Ok(ParentRef {
                    id,
                    commitment: self.group_state(&id)?.commitment()?,
                })
            })
            .collect()
    }

    pub fn group_state(&self, group: &Id) -> Result<GroupState> {
        let state = GroupState::new(
            &self.community,
            self.groups.get(group).ok_or(Error::Invalid)?,
        );
        state.validate()?;
        Ok(state)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParentRef {
    pub id: Id,
    pub commitment: Id,
}
