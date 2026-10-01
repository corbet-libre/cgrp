use crate::{DAY, Error, Id, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Activity {
    Message,
    Reaction,
    Welcome { receipt: Id },
    Introduction { receipt: Id },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
struct Day {
    messages: u16,
    reactions: u16,
    welcomes: BTreeSet<Id>,
    introductions: BTreeSet<Id>,
}

/// Per-member, per-group ledger. Store in the encrypted device checkpoint only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ActivityLedger {
    now: u64,
    days: BTreeMap<u64, Day>,
}

impl ActivityLedger {
    /// Receipted events must originate in a verified receipt capability. This
    /// counter alone never grants credit or supplies an accounting proof.
    pub fn record(&mut self, event: Activity, now: u64, max_receipts_per_day: usize) -> Result<()> {
        if now < self.now {
            return Err(Error::Clock);
        }
        let day = now / DAY;
        let mut next = self.clone();
        next.now = now;
        next.days.retain(|d, _| day.saturating_sub(*d) < 7);
        let duplicate = match event {
            Activity::Welcome { receipt } => {
                next.days.values().any(|d| d.welcomes.contains(&receipt))
            }
            Activity::Introduction { receipt } => next
                .days
                .values()
                .any(|d| d.introductions.contains(&receipt)),
            Activity::Message | Activity::Reaction => false,
        };
        if duplicate {
            return Err(Error::Conflict);
        }
        let introductions: usize = next.days.values().map(|d| d.introductions.len()).sum();
        let row = next.days.entry(day).or_default();
        match event {
            Activity::Message => {
                row.messages = row.messages.saturating_add(1).min(2);
            }
            Activity::Reaction => {
                row.reactions = row.reactions.saturating_add(1).min(4);
            }
            Activity::Welcome { receipt } => {
                if row.welcomes.len() >= max_receipts_per_day {
                    return Err(Error::Capacity);
                }
                row.welcomes.insert(receipt);
            }
            Activity::Introduction { receipt } => {
                if introductions >= 2 {
                    return Err(Error::Capacity);
                }
                row.introductions.insert(receipt);
            }
        }
        *self = next;
        Ok(())
    }

    pub fn points_tenths(&self, now: u64) -> Result<u32> {
        if now < self.now {
            return Err(Error::Clock);
        }
        let day = now / DAY;
        Ok(self
            .days
            .iter()
            .filter(|(d, _)| day.saturating_sub(**d) < 7)
            .map(|(_, r)| {
                u32::from(r.messages) * 10
                    + u32::from(r.reactions) * 3
                    + r.welcomes.len() as u32 * 20
                    + r.introductions.len() as u32 * 30
            })
            .sum())
    }
}
