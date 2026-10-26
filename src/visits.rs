//! Device-local WasHere recording (P6b).
//!
//! When the member actually OPENS a group, the device records at most one
//! `WasHere` per member, group and 6-hour bucket. The fact waits out a random
//! 0..60 s jitter (0..=4 ticks) and is then piggybacked on the next ordinary
//! group exchange the device builds anyway; it is never transmitted alone and
//! never delivered offline later. The payload carries only "was here": member,
//! group and visit bucket, never what was read. Counts are by member, never by
//! device: the ledger takes no device input at all, and duplicate opens from
//! any of the member's devices collapse to the one pending fact.
//!
//! Design: `DESIGN-state-model-2026-10-26.md` §5.1 (warm-seat mechanics:
//! one effective check-in per member/group/bucket, secret jitter, piggyback,
//! short visit supplies nothing without a live exchange). Decisions in
//! `STATUS.md` rows of 2026-10-26 (count members, never devices).
//!
//! Scope: this module is the device-side recording and release decision only.
//! It performs no signing, no custody, no key handling and no transmission.
//! The agreed fact (`warm::CheckIn`) is derived later by the agreement layer,
//! which authenticates the sender through the existing MLS leaf credential
//! (like any group exchange) and freezes `n`/sequence there. No new signed
//! format is introduced here, and none is needed: the sender is whoever the
//! group's MLS already authenticated. MLS removal of a due free seat is out
//! of scope.

use crate::{Error, Id, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Latest release jitter in ticks (4 ticks of 15 s = 60 s). The caller draws
/// the actual 0..=4 delay from its own entropy; the ledger only enforces the
/// bound, so tests stay deterministic.
pub const MAX_JITTER_TICKS: u64 = 4;

/// "Was here": the whole payload of one visit. Exactly the member, the group
/// and the start of the 6-hour bucket the opening fell into. No device, no
/// message reference, no read state, no counter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WasHere {
    /// Community-local member binding; counts key on this, never on devices.
    pub member: String,
    /// Group the member opened.
    pub group: Id,
    /// Start of the visit bucket in ticks, aligned to `BUCKET_TICKS`.
    pub bucket_start: u64,
}

/// Outcome of recording one opening.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordOutcome {
    /// A new pending fact. `due_at` is the tick from which it may ride the
    /// next ordinary group exchange.
    Recorded { bucket_start: u64, due_at: u64 },
    /// This member/group/bucket already has a pending or supplied fact:
    /// at most one per bucket, so the repeat opening records nothing.
    Duplicate,
}

/// Pending and already-supplied WasHere facts of this device, in ticks.
/// Memory only: closing the group or going offline drops undelivered pending
/// facts without marking them supplied, so nothing is ever delivered offline.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VisitLedger {
    pending: BTreeMap<(String, Id, u64), u64>,
    sent: BTreeSet<(String, Id, u64)>,
}

impl VisitLedger {
    pub fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            sent: BTreeSet::new(),
        }
    }

    pub fn record_open(
        &mut self,
        member: &str,
        group: &Id,
        now_ticks: u64,
        jitter_ticks: u64,
    ) -> Result<RecordOutcome> {
        if member.is_empty() || member.len() > 200 || jitter_ticks > MAX_JITTER_TICKS {
            return Err(Error::Invalid);
        }
        let bucket_start = now_ticks - (now_ticks % crate::warm::BUCKET_TICKS);
        let key = (member.to_owned(), *group, bucket_start);
        if self.pending.contains_key(&key) || self.sent.contains(&key) {
            return Ok(RecordOutcome::Duplicate);
        }
        let due_at = now_ticks.checked_add(jitter_ticks).ok_or(Error::Capacity)?;
        self.pending.insert(key, due_at);
        Ok(RecordOutcome::Recorded {
            bucket_start,
            due_at,
        })
    }

    pub fn due_for_exchange(&self, now_ticks: u64) -> Vec<WasHere> {
        let mut due: Vec<WasHere> = self
            .pending
            .iter()
            .filter(|((_, _, bucket_start), due_at)| {
                **due_at <= now_ticks && *bucket_start <= now_ticks
            })
            .map(|((member, group, bucket_start), _)| WasHere {
                member: member.clone(),
                group: *group,
                bucket_start: *bucket_start,
            })
            .collect();
        due.sort_by(|a, b| {
            (&a.member, &a.group, &a.bucket_start).cmp(&(&b.member, &b.group, &b.bucket_start))
        });
        due
    }

    pub fn mark_exchanged(&mut self, facts: &[WasHere]) -> Result<()> {
        for fact in facts {
            let key = (fact.member.clone(), fact.group, fact.bucket_start);
            if self.pending.remove(&key).is_none() {
                return Err(Error::Invalid);
            }
            self.sent.insert(key);
        }
        Ok(())
    }

    pub fn drop_undelivered(&mut self) {
        self.pending.clear();
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn is_sent(&self, member: &str, group: &Id, bucket_start: u64) -> bool {
        self.sent
            .contains(&(member.to_owned(), *group, bucket_start))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warm::BUCKET_TICKS;

    fn group(id: u8) -> Id {
        [id; 32]
    }

    #[test]
    fn open_records_one_pending_visit_per_bucket() {
        let mut ledger = VisitLedger::new();
        let g = group(1);
        let first = ledger.record_open("a", &g, 100, 2).expect("valid open");
        assert_eq!(
            first,
            RecordOutcome::Recorded {
                bucket_start: 0,
                due_at: 102
            }
        );
        assert_eq!(ledger.pending_count(), 1);
        // A repeat opening in the same bucket records nothing more.
        let again = ledger.record_open("a", &g, 150, 0).expect("valid open");
        assert_eq!(again, RecordOutcome::Duplicate);
        assert_eq!(ledger.pending_count(), 1);
    }

    #[test]
    fn jitter_holds_the_fact_until_due() {
        let mut ledger = VisitLedger::new();
        let g = group(1);
        ledger.record_open("a", &g, 100, 3).expect("valid open");
        assert!(ledger.due_for_exchange(102).is_empty());
        let due = ledger.due_for_exchange(103);
        assert_eq!(
            due,
            vec![WasHere {
                member: "a".into(),
                group: g,
                bucket_start: 0,
            }]
        );
    }

    #[test]
    fn exchange_marks_sent_and_blocks_resend_in_bucket() {
        let mut ledger = VisitLedger::new();
        let g = group(1);
        ledger.record_open("a", &g, 100, 0).expect("valid open");
        let due = ledger.due_for_exchange(100);
        assert_eq!(due.len(), 1);
        ledger.mark_exchanged(&due).expect("pending fact exchanges");
        assert!(ledger.is_sent("a", &g, 0));
        // Closing the group drops nothing already supplied: no second fact.
        ledger.drop_undelivered();
        assert_eq!(
            ledger.record_open("a", &g, 150, 0),
            Ok(RecordOutcome::Duplicate)
        );
    }

    #[test]
    fn short_visit_without_exchange_leaves_nothing_agreed() {
        let mut ledger = VisitLedger::new();
        let g = group(1);
        ledger.record_open("a", &g, 100, 0).expect("valid open");
        // No ordinary exchange was built while live: going offline drops the
        // pending fact instead of delivering it later.
        ledger.drop_undelivered();
        assert!(ledger.due_for_exchange(10_000).is_empty());
        assert!(!ledger.is_sent("a", &g, 0));
        // A new live visit in the same bucket may still supply the one fact.
        assert_eq!(
            ledger.record_open("a", &g, 150, 0),
            Ok(RecordOutcome::Recorded {
                bucket_start: 0,
                due_at: 150
            })
        );
    }

    #[test]
    fn payload_carries_only_was_here() {
        let fact = WasHere {
            member: "a".into(),
            group: group(7),
            bucket_start: 2 * BUCKET_TICKS,
        };
        let value = serde_json::to_value(&fact).expect("serializes");
        let keys: BTreeSet<&str> = value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, BTreeSet::from(["bucket_start", "group", "member"]));
    }

    #[test]
    fn members_count_not_devices() {
        // The ledger takes no device input at all: opens from any of the
        // member's devices are the same member opening.
        let mut ledger = VisitLedger::new();
        let g = group(1);
        ledger.record_open("a", &g, 100, 0).expect("valid open");
        ledger.record_open("a", &g, 120, 0).expect("valid open");
        assert_eq!(ledger.pending_count(), 1);
        // Two members opening the same group supply two facts.
        ledger.record_open("b", &g, 100, 0).expect("valid open");
        let mut due = ledger.due_for_exchange(200);
        due.sort_by(|x, y| x.member.cmp(&y.member));
        assert_eq!(due.len(), 2);
        assert!(due.iter().all(|f| f.group == g && f.bucket_start == 0));
        // One member opening two groups supplies one fact per group.
        ledger.mark_exchanged(&due).expect("exchanges both");
        let h = group(2);
        ledger.record_open("a", &h, 100, 0).expect("valid open");
        let due = ledger.due_for_exchange(200);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].group, h);
    }

    #[test]
    fn next_bucket_records_again() {
        let mut ledger = VisitLedger::new();
        let g = group(1);
        ledger.record_open("a", &g, 100, 0).expect("valid open");
        ledger
            .mark_exchanged(&ledger.due_for_exchange(100))
            .expect("exchanges");
        let next = BUCKET_TICKS + 10;
        assert_eq!(
            ledger.record_open("a", &g, next, 1),
            Ok(RecordOutcome::Recorded {
                bucket_start: BUCKET_TICKS,
                due_at: next + 1
            })
        );
    }

    #[test]
    fn invalid_inputs_are_refused() {
        let mut ledger = VisitLedger::new();
        let g = group(1);
        assert_eq!(ledger.record_open("", &g, 100, 0), Err(Error::Invalid));
        assert_eq!(
            ledger.record_open(&"a".repeat(201), &g, 100, 0),
            Err(Error::Invalid)
        );
        assert_eq!(
            ledger.record_open("a", &g, 100, MAX_JITTER_TICKS + 1),
            Err(Error::Invalid)
        );
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn exchange_marks_only_pending_facts() {
        let mut ledger = VisitLedger::new();
        let ghost = WasHere {
            member: "ghost".into(),
            group: group(9),
            bucket_start: 0,
        };
        assert_eq!(ledger.mark_exchanged(&[ghost]), Err(Error::Invalid));
        assert_eq!(ledger.mark_exchanged(&[]), Ok(()));
    }

    #[test]
    fn peeking_never_releases_or_transmits() {
        // The ledger has no transport: peeking at due facts changes nothing,
        // so only an actual exchange built by the caller consumes them.
        let mut ledger = VisitLedger::new();
        let g = group(1);
        ledger.record_open("a", &g, 100, 0).expect("valid open");
        let first = ledger.due_for_exchange(100);
        let second = ledger.due_for_exchange(100);
        assert_eq!(first, second);
        assert_eq!(ledger.pending_count(), 1);
        assert!(!ledger.is_sent("a", &g, 0));
    }
}
