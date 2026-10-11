//! Missing parents are private preparation inputs, never a replacement checkpoint.
use super::*;

/// Prepare using exact invitation-authenticated parents missing from this
/// device's original checkpoint. No existing group can be overwritten. The
/// candidate retains the original base and rechecks all parent authority at
/// publication, alongside the unchanged original consent and policy decisions.
pub fn prepare_with_parents(
    state: &Snapshot,
    request: &Request,
    parents: &[crate::GroupState],
    source: &impl PolicySource,
    authority: &impl Authority,
    now: u64,
    max_groups: usize,
) -> Result<Candidate> {
    prepare_at_with_parents(
        state,
        request,
        parents,
        source,
        authority,
        (now, now),
        max_groups,
    )
}

pub(super) fn prepare_at_with_parents(
    state: &Snapshot,
    request: &Request,
    parents: &[crate::GroupState],
    source: &impl PolicySource,
    authority: &impl Authority,
    time: (u64, u64),
    max_groups: usize,
) -> Result<Candidate> {
    if parents.is_empty() {
        return prepare_at(state, request, source, authority, time, max_groups);
    }
    if parents.len() > 2
        || request.parents.len() > 2
        || request
            .parents
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
        || state
            .groups
            .len()
            .checked_add(parents.len())
            .is_none_or(|n| n > max_groups)
    {
        return Err(Error::Capacity);
    }
    let missing: Vec<_> = request
        .parents
        .iter()
        .filter(|parent| !state.groups.contains_key(&parent.id))
        .collect();
    if missing.len() != parents.len() {
        return Err(Error::Conflict);
    }
    let policy = source.current(&state.community, time.1)?;
    policy.validate(time.1)?;
    let mut working = state.clone();
    for (parent, expected) in parents.iter().zip(missing) {
        if parent.community() != state.community
            || parent.id() != &expected.id
            || parent.commitment()? != expected.commitment
            || parent.policy_epoch() > policy.epoch
        {
            return Err(Error::Authority);
        }
        authority.parent(parent, request, time.1)?;
        let group = parent.imported_group()?;
        // The map was cloned from the actual original base, and only missing
        // exact parent IDs reach this branch. Existing history is never replaced.
        if working.groups.insert(*parent.id(), group).is_some() {
            return Err(Error::Conflict);
        }
    }
    let mut candidate = prepare_at(&working, request, source, authority, time, max_groups)?;
    if candidate.policy != policy {
        return Err(Error::Policy);
    }
    candidate.base = state.clone();
    candidate.imported_parents = parents.to_vec();
    Ok(candidate)
}
