use crate::{DAY, Error, Id, Policy, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Suggestion {
    Fission { left: usize, right: usize },
    Crowded,
    Fusion { other: Id, union: usize },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SuggestionLedger {
    shown: BTreeMap<Id, u64>,
    declined: BTreeMap<Id, u64>,
}

impl SuggestionLedger {
    pub fn available(&self, group: &Id, now: u64, policy: &Policy) -> Result<bool> {
        for map in [&self.shown, &self.declined] {
            if map.get(group).is_some_and(|at| *at > now) {
                return Err(Error::Clock);
            }
        }
        Ok(!self
            .shown
            .get(group)
            .is_some_and(|at| now - at < policy.suggestion_cooldown)
            && !self
                .declined
                .get(group)
                .is_some_and(|at| now - at < policy.decline_cooldown))
    }
    pub fn shown(&mut self, group: Id, now: u64) {
        self.shown.insert(group, now);
    }
    pub fn declined(&mut self, group: Id, now: u64) {
        self.declined.insert(group, now);
    }
    pub fn prune(&mut self, now: u64) {
        self.shown
            .retain(|_, at| now.saturating_sub(*at) < 14 * DAY);
        self.declined
            .retain(|_, at| now.saturating_sub(*at) < 14 * DAY);
    }
}

/// Local co-reply edges, weighted by observed exchanges. No server telemetry.
/// Evaluate a proposed two-part cut, not a new community-detection algorithm.
pub fn fission(
    roster: &BTreeSet<String>,
    left: &BTreeSet<String>,
    edges: &[(String, String, u32)],
    policy: &Policy,
) -> Result<Option<Suggestion>> {
    if !left.is_subset(roster) || left.is_empty() || left.len() == roster.len() {
        return Err(Error::Invalid);
    }
    if roster.len() >= usize::from(policy.pressure_at) {
        return Ok(Some(Suggestion::Crowded));
    }
    if roster.len() < usize::from(policy.suggest_at) {
        return Ok(None);
    }
    let mut total = 0.0;
    let mut inside = [0.0; 2];
    let mut degree = [0.0; 2];
    for (a, b, weight) in edges {
        if a == b || !roster.contains(a) || !roster.contains(b) {
            return Err(Error::Invalid);
        }
        let i = usize::from(!left.contains(a));
        let j = usize::from(!left.contains(b));
        let w = f64::from(*weight);
        total += w;
        degree[i] += w;
        degree[j] += w;
        if i == j {
            inside[i] += w;
        }
    }
    if total == 0.0 {
        return Ok(None);
    }
    let modularity: f64 = (0..2)
        .map(|i| inside[i] / total - (degree[i] / (2.0 * total)).powi(2))
        .sum();
    Ok(
        (modularity >= policy.modularity).then_some(Suggestion::Fission {
            left: left.len(),
            right: roster.len() - left.len(),
        }),
    )
}

pub fn fusion(
    actor: &str,
    first: &BTreeSet<String>,
    second: &BTreeSet<String>,
    other: Id,
    policy: &Policy,
) -> Option<Suggestion> {
    if !first.contains(actor) || !second.contains(actor) {
        return None;
    }
    let union = first.union(second).count();
    if union > usize::from(policy.circle_max) {
        return None;
    }
    let overlap = first.intersection(second).count() as f64 / union as f64;
    (overlap >= policy.overlap).then_some(Suggestion::Fusion { other, union })
}
