//! Warm seats and room level as pure derivation.
//!
//! Design: `DESIGN-state-model-2026-10-26.md` §5 (seat mechanics, hysteresis
//! fold) and §12 review traces; decisions in `STATUS.md` rows of 2026-10-26
//! (warm seats, "groups float through state space", Q5 one conversation,
//! additive forks). Final decisions override the design where they differ:
//!
//! - Growth is automatic (no consent fork); shrinking is automatic too, with
//!   hysteresis. This withdraws the design's "expansion needs a new consent
//!   fork" row.
//! - Room states follow the warm count `W`: 0 gone, 1 alone, 2 personal,
//!   3-12 circle, 13-42 ingroup, 43-250 public (256 technical ceiling).
//!   Shrink thresholds: public becomes ingroup at `W <= 36`, ingroup becomes
//!   circle at `W <= 10`.
//! - Seats are warm, cooling or free, derived from agreed `WasHere` facts.
//!   Only members count, never devices.
//!
//! This module is deliberately unwired: it takes its own minimal fact inputs
//! (check-ins, releases, current eligibility) and a community tick, and
//! derives seats and levels with no clocks, network, storage, MLS or existing
//! group flows. The agreement layer owns signature checks, the `n == W before`
//! check-in validity rule and roster caps; this module consumes the frozen `n`
//! as agreed.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Community seconds per tick. Aligned with the state-model checkpoint tick.
pub const TICK_SECONDS: u64 = 15;
/// Six community hours in ticks: at most one effective check-in per
/// member and bucket.
pub const BUCKET_TICKS: u64 = 6 * 3_600 / TICK_SECONDS;
/// Warm-duration clamp bounds in ticks: 28 days down to 7 days.
pub const WARM_MAX_TICKS: u64 = 28 * 86_400 / TICK_SECONDS;
/// Warm-duration clamp bounds in ticks: 28 days down to 7 days.
pub const WARM_MIN_TICKS: u64 = 7 * 86_400 / TICK_SECONDS;
/// A cooling seat cannot be reclaimed before one day past its warm end.
pub const COOL_MIN_TICKS: u64 = 86_400 / TICK_SECONDS;
/// A cooling seat is free on its own after 28 days past its warm end.
pub const COOL_MAX_TICKS: u64 = 28 * 86_400 / TICK_SECONDS;
/// Technical seat ceiling (256); the user-facing public room limit is 250.
pub const MAX_SEATS: u64 = 256;
/// User-facing public room limit; the six seats of cushion absorb joins in
/// flight, pending leaves and fork overlaps.
pub const VISIBLE_CAP: u64 = 250;

/// Growth edges of the warm-count ladder.
pub const ENTER_CIRCLE: u64 = 3;
/// Growth edges of the warm-count ladder.
pub const ENTER_INGROUP: u64 = 13;
/// Growth edges of the warm-count ladder.
pub const ENTER_PUBLIC: u64 = 43;
/// A public room becomes an ingroup at or below this warm count.
pub const SHRINK_PUBLIC: u64 = 36;
/// An ingroup becomes a circle at or below this warm count.
pub const SHRINK_INGROUP: u64 = 10;

/// Warm duration `D(n)` in ticks, with `n` frozen at the check-in:
/// `clamp(ceil(28 days / sqrt(max(1,n)/4)), 7 days, 28 days)`, rounded up to a
/// whole tick. Later joins never shorten a frozen deadline.
pub fn warm_duration_ticks(n: u64) -> u64 {
    // D(n) = ceil(NUM / sqrt(n)) with NUM = 2 * WARM_MAX_TICKS, since
    // 28 days / sqrt(n/4) = 56 days / sqrt(n). Exact integer binary search
    // for the smallest D with D * sqrt(n) >= NUM, i.e. D^2 * n >= NUM^2;
    // u128 holds the squares with wide margin.
    const NUM: u64 = 2 * WARM_MAX_TICKS;
    const NUM_SQ: u128 = NUM as u128 * NUM as u128;
    let n = n.max(1) as u128;
    let mut lo = 0u64;
    let mut hi = NUM;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if (mid as u128) * (mid as u128) * n >= NUM_SQ {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo.clamp(WARM_MIN_TICKS, WARM_MAX_TICKS)
}

/// Agreed visit fact (minimal inputs). The agreement layer authenticates the
/// member device, the bucket and the frozen size input; devices are carried
/// only so member dedup across devices is observable, never counted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckIn {
    /// Community-local member binding; seats and counts key on this.
    pub member: String,
    /// Authorized device lineage that reported the visit; ignored for counts.
    pub device: String,
    /// Start of the visit bucket (`v`), in ticks, aligned to `BUCKET_TICKS`.
    pub bucket_start: u64,
    /// `max(1, W immediately before this check-in)`, frozen as agreed.
    pub frozen_n: u64,
    /// Agreed sequence; orders same-tick facts and breaks warm-end ties.
    pub seq: u64,
}

/// Agreed capacity-admission fact: reclaiming one sufficiently cooling seat
/// for an accepted join. Targets one seat generation exactly, so a newer
/// agreed visit invalidates a stale proposal before commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SeatRelease {
    /// Member whose cooling seat is reclaimed.
    pub member: String,
    /// Tick of the joint reclamation-and-join fact.
    pub at_tick: u64,
    /// Agreed sequence; orders same-tick facts.
    pub seq: u64,
    /// Warm end of the seat generation this release targets; must equal the
    /// member's latest warm end at `at_tick`.
    pub expected_warm_end: u64,
}

/// Derived seat state at the evaluated tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seat {
    Warm,
    Cooling,
    Free,
}

/// One member's derived seat. Ends are `Some` whenever the member is eligible
/// and has an effective check-in at or before the evaluated tick, even when
/// the seat itself is already free.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeatView {
    pub member: String,
    pub state: Seat,
    pub warm_end: Option<u64>,
    pub reclaimable_at: Option<u64>,
    pub free_at: Option<u64>,
}

/// Derived seats and warm count `W` (distinct warm members) at one tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeatsView {
    pub seats: Vec<SeatView>,
    pub warm: u64,
}

/// Derive every seat and the warm count at tick `now`.
///
/// `ineligible` holds members without a seat incarnation: left, removed, or
/// not admitted. Facts the agreement layer would refuse (empty member,
/// unaligned bucket, zero frozen size, mistimed or out-of-order releases,
/// stale generations) are refused with `Error::Invalid`.
pub fn evaluate(
    checkins: &[CheckIn],
    ineligible: &BTreeSet<String>,
    releases: &[SeatRelease],
    now: u64,
) -> Result<SeatsView> {
    for c in checkins {
        if c.member.is_empty()
            || c.member.len() > 200
            || c.device.is_empty()
            || c.device.len() > 200
            || c.bucket_start % BUCKET_TICKS != 0
            || c.frozen_n == 0
        {
            return Err(Error::Invalid);
        }
    }
    for r in releases {
        if r.member.is_empty() || r.member.len() > 200 {
            return Err(Error::Invalid);
        }
    }
    // At most one effective check-in per member and bucket: the canonical
    // first (smallest agreed sequence) wins; exact duplicates have one
    // effect. Devices never create extra seats.
    let mut first: BTreeMap<(String, u64), &CheckIn> = BTreeMap::new();
    for c in checkins {
        let key = (c.member.clone(), c.bucket_start / BUCKET_TICKS);
        match first.get(&key) {
            Some(prev) if prev.seq <= c.seq => {}
            _ => {
                first.insert(key, c);
            }
        }
    }
    let mut by_member: BTreeMap<&str, Vec<&CheckIn>> = BTreeMap::new();
    for c in first.values() {
        by_member.entry(c.member.as_str()).or_default().push(*c);
    }
    for visits in by_member.values_mut() {
        visits.sort_by_key(|c| (c.bucket_start, c.seq));
    }
    // Latest effective visit at or before `t`, with its frozen warm end.
    let latest_at = |member: &str, t: u64| -> Result<Option<(u64, u64)>> {
        let mut out = None;
        for c in &by_member[member] {
            if c.bucket_start > t {
                break;
            }
            let end = c
                .bucket_start
                .checked_add(warm_duration_ticks(c.frozen_n))
                .ok_or(Error::Capacity)?;
            out = Some((end, c.seq));
        }
        Ok(out)
    };
    // Reclaimable seats at `t`, oldest first: ascending (warm end, agreed
    // sequence). Only sufficiently cooling seats, never a chosen target.
    let pressure_order = |t: u64, freed: &BTreeSet<(String, u64)>| -> Result<Vec<String>> {
        let mut order: Vec<(u64, u64, String)> = Vec::new();
        for member in by_member.keys() {
            if ineligible.contains(*member) {
                continue;
            }
            let Some((end, seq)) = latest_at(member, t)? else {
                continue;
            };
            let (Some(min), Some(max)) = (
                end.checked_add(COOL_MIN_TICKS),
                end.checked_add(COOL_MAX_TICKS),
            ) else {
                continue;
            };
            if min <= t && t < max && !freed.contains(&(member.to_string(), end)) {
                order.push((end, seq, member.to_string()));
            }
        }
        order.sort();
        Ok(order.into_iter().map(|(_, _, m)| m).collect())
    };
    // Validate every release in canonical order, whenever it fires. A repeat
    // for an already freed generation is a no-effect success; anything else
    // that frees nobody, mistimes, skips the oldest seat or targets a stale
    // generation is refused. Validity is timeless; only releases at or before
    // `now` take effect below.
    let mut ordered: Vec<&SeatRelease> = releases.iter().collect();
    ordered.sort_by_key(|r| (r.at_tick, r.seq));
    let mut freed: BTreeSet<(String, u64)> = BTreeSet::new();
    let mut applied: Vec<(String, u64, u64)> = Vec::new();
    for r in ordered {
        if freed.contains(&(r.member.clone(), r.expected_warm_end)) {
            continue;
        }
        if !by_member.contains_key(r.member.as_str()) || ineligible.contains(&r.member) {
            return Err(Error::Invalid);
        }
        let Some((end, _)) = latest_at(&r.member, r.at_tick)? else {
            return Err(Error::Invalid);
        };
        if end != r.expected_warm_end {
            return Err(Error::Invalid);
        }
        let (Some(min), Some(max)) = (
            end.checked_add(COOL_MIN_TICKS),
            end.checked_add(COOL_MAX_TICKS),
        ) else {
            return Err(Error::Invalid);
        };
        if !(min <= r.at_tick && r.at_tick < max) {
            return Err(Error::Invalid);
        }
        if pressure_order(r.at_tick, &freed)?.first() != Some(&r.member) {
            return Err(Error::Invalid);
        }
        freed.insert((r.member.clone(), end));
        applied.push((r.member.clone(), end, r.at_tick));
    }
    let effective_freed: BTreeSet<(String, u64)> = applied
        .into_iter()
        .filter(|(_, _, at)| *at <= now)
        .map(|(m, e, _)| (m, e))
        .collect();
    let mut seats = Vec::new();
    let mut warm = 0u64;
    for member in by_member.keys() {
        let mut view = SeatView {
            member: member.to_string(),
            state: Seat::Free,
            warm_end: None,
            reclaimable_at: None,
            free_at: None,
        };
        if ineligible.contains(*member) {
            seats.push(view);
            continue;
        }
        let Some((end, _)) = latest_at(member, now)? else {
            // No seat incarnation at this tick (first visit still ahead):
            // not listed, so historical views stay identical.
            continue;
        };
        view.warm_end = Some(end);
        view.reclaimable_at = end.checked_add(COOL_MIN_TICKS);
        view.free_at = end.checked_add(COOL_MAX_TICKS);
        let Some(max) = end.checked_add(COOL_MAX_TICKS) else {
            return Err(Error::Capacity);
        };
        view.state = if now < end {
            warm += 1;
            Seat::Warm
        } else if now >= max || effective_freed.contains(&(member.to_string(), end)) {
            Seat::Free
        } else {
            Seat::Cooling
        };
        seats.push(view);
    }
    Ok(SeatsView { seats, warm })
}

/// Room nature as a state of the warm count, with hysteresis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomLevel {
    Gone,
    Alone,
    Personal,
    Circle,
    Ingroup,
    Public,
}

/// One hysteresis step. Growth is automatic (no consent fork): any prior
/// level reaches ingroup at 13 and public at 43. Shrinking keeps a public
/// room public down to 36 and an ingroup an ingroup down to 10.
pub fn next_level(prior: RoomLevel, warm: u64) -> RoomLevel {
    if warm == 0 {
        return RoomLevel::Gone;
    }
    if warm == 1 {
        return RoomLevel::Alone;
    }
    if warm == 2 {
        return RoomLevel::Personal;
    }
    if warm >= ENTER_PUBLIC {
        return RoomLevel::Public;
    }
    if warm >= ENTER_INGROUP {
        if prior == RoomLevel::Public && warm > SHRINK_PUBLIC {
            return RoomLevel::Public;
        }
        return RoomLevel::Ingroup;
    }
    if warm <= SHRINK_INGROUP {
        return RoomLevel::Circle;
    }
    if prior == RoomLevel::Ingroup || prior == RoomLevel::Public {
        return RoomLevel::Ingroup;
    }
    RoomLevel::Circle
}

/// Replay warm counts in canonical order from an initial level. A newborn
/// conversation starts at circle; every later step is automatic in both
/// directions.
pub fn replay(initial: RoomLevel, warm_series: &[u64]) -> RoomLevel {
    warm_series
        .iter()
        .fold(initial, |level, w| next_level(level, *w))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkin(member: &str, device: &str, bucket: u64, frozen_n: u64, seq: u64) -> CheckIn {
        CheckIn {
            member: member.into(),
            device: device.into(),
            bucket_start: bucket * BUCKET_TICKS,
            frozen_n,
            seq,
        }
    }

    fn view_at(checkins: &[CheckIn], now: u64) -> SeatsView {
        evaluate(checkins, &BTreeSet::new(), &[], now).expect("valid facts derive")
    }

    #[test]
    fn durations_clamp_and_follow_size() {
        assert_eq!(warm_duration_ticks(0), WARM_MAX_TICKS);
        assert_eq!(warm_duration_ticks(1), WARM_MAX_TICKS);
        assert_eq!(warm_duration_ticks(2), WARM_MAX_TICKS);
        assert_eq!(warm_duration_ticks(3), WARM_MAX_TICKS);
        assert_eq!(warm_duration_ticks(4), WARM_MAX_TICKS);
        assert_eq!(warm_duration_ticks(9), 107_520);
        assert_eq!(warm_duration_ticks(16), 80_640);
        assert_eq!(warm_duration_ticks(64), WARM_MIN_TICKS);
        assert_eq!(warm_duration_ticks(65), WARM_MIN_TICKS);
        assert_eq!(warm_duration_ticks(256), WARM_MIN_TICKS);
        assert_eq!(warm_duration_ticks(10_000), WARM_MIN_TICKS);
    }

    #[test]
    fn durations_round_up_and_shrink_with_size() {
        let mut last = u64::MAX;
        for n in [1, 2, 4, 5, 9, 13, 16, 42, 64, 100, 250] {
            let d = warm_duration_ticks(n);
            assert!(d <= last, "D({n}) = {d} grows after {last}");
            assert!(
                (WARM_MIN_TICKS..=WARM_MAX_TICKS).contains(&d),
                "D({n}) = {d} escapes the 7..28 day clamp"
            );
            last = d;
        }
    }

    #[test]
    fn seat_warms_then_cools_then_frees() {
        let facts = vec![checkin("a", "a-phone", 0, 64, 0)];
        let e = WARM_MIN_TICKS;
        assert_eq!(view_at(&facts, 0).warm, 1);
        let before = view_at(&facts, e - 1);
        assert_eq!(before.seats[0].state, Seat::Warm);
        assert_eq!(before.seats[0].warm_end, Some(e));
        assert_eq!(before.seats[0].reclaimable_at, Some(e + COOL_MIN_TICKS));
        assert_eq!(before.seats[0].free_at, Some(e + COOL_MAX_TICKS));
        assert_eq!(view_at(&facts, e).seats[0].state, Seat::Cooling);
        assert_eq!(
            view_at(&facts, e + COOL_MIN_TICKS - 1).seats[0].state,
            Seat::Cooling
        );
        assert_eq!(
            view_at(&facts, e + COOL_MAX_TICKS - 1).seats[0].state,
            Seat::Cooling
        );
        let freed = view_at(&facts, e + COOL_MAX_TICKS);
        assert_eq!(freed.seats[0].state, Seat::Free);
        assert_eq!(freed.warm, 0);
    }

    #[test]
    fn cold_seat_frees_only_by_capacity_or_max() {
        let facts = vec![checkin("a", "a-phone", 0, 64, 0)];
        let e = WARM_MIN_TICKS;
        let early = SeatRelease {
            member: "a".into(),
            at_tick: e + COOL_MIN_TICKS - 1,
            seq: 0,
            expected_warm_end: e,
        };
        assert!(evaluate(&facts, &BTreeSet::new(), &[early], e).is_err());
        let due = SeatRelease {
            member: "a".into(),
            at_tick: e + COOL_MIN_TICKS,
            seq: 0,
            expected_warm_end: e,
        };
        let view = evaluate(&facts, &BTreeSet::new(), &[due], e + COOL_MIN_TICKS).unwrap();
        assert_eq!(view.seats[0].state, Seat::Free);
        assert_eq!(view.warm, 0);
    }

    #[test]
    fn releases_take_the_oldest_cooling_seat_first() {
        let facts = vec![
            checkin("old", "old-phone", 0, 64, 0),
            checkin("new", "new-phone", 10, 64, 1),
        ];
        let e_old = WARM_MIN_TICKS;
        let e_new = 10 * BUCKET_TICKS + WARM_MIN_TICKS;
        assert!(e_old < e_new);
        let at = e_new + COOL_MIN_TICKS;
        let wrong_first = SeatRelease {
            member: "new".into(),
            at_tick: at,
            seq: 0,
            expected_warm_end: e_new,
        };
        assert!(evaluate(&facts, &BTreeSet::new(), &[wrong_first], at).is_err());
        let right_first = SeatRelease {
            member: "old".into(),
            at_tick: at,
            seq: 0,
            expected_warm_end: e_old,
        };
        let view = evaluate(&facts, &BTreeSet::new(), &[right_first], at).unwrap();
        let state = |m: &str| view.seats.iter().find(|s| s.member == m).unwrap().state;
        assert_eq!(state("old"), Seat::Free);
        assert_eq!(state("new"), Seat::Cooling);
    }

    #[test]
    fn stale_release_dies_on_revisit() {
        let e1 = WARM_MIN_TICKS;
        let facts = vec![
            checkin("a", "a-phone", 0, 64, 0),
            checkin("a", "a-phone", 1, 64, 1),
        ];
        let e2 = BUCKET_TICKS + WARM_MIN_TICKS;
        assert_ne!(e1, e2);
        let stale = SeatRelease {
            member: "a".into(),
            at_tick: e2 + COOL_MIN_TICKS,
            seq: 0,
            expected_warm_end: e1,
        };
        assert!(evaluate(&facts, &BTreeSet::new(), &[stale], e2 + COOL_MIN_TICKS).is_err());
        let fresh = SeatRelease {
            member: "a".into(),
            at_tick: e2 + COOL_MIN_TICKS,
            seq: 0,
            expected_warm_end: e2,
        };
        let view = evaluate(&facts, &BTreeSet::new(), &[fresh], e2 + COOL_MIN_TICKS).unwrap();
        assert_eq!(view.seats[0].state, Seat::Free);
    }

    #[test]
    fn duplicate_release_is_a_no_effect_success() {
        let facts = vec![checkin("a", "a-phone", 0, 64, 0)];
        let e = WARM_MIN_TICKS;
        let release = SeatRelease {
            member: "a".into(),
            at_tick: e + COOL_MIN_TICKS,
            seq: 0,
            expected_warm_end: e,
        };
        let view = evaluate(
            &facts,
            &BTreeSet::new(),
            &[release.clone(), release],
            e + COOL_MIN_TICKS,
        )
        .unwrap();
        assert_eq!(view.seats[0].state, Seat::Free);
        assert_eq!(view.warm, 0);
    }

    #[test]
    fn members_count_once_across_devices() {
        let same_bucket = vec![
            checkin("a", "a-phone", 0, 1, 0),
            checkin("a", "a-tablet", 0, 1, 1),
        ];
        let view = view_at(&same_bucket, 0);
        assert_eq!(view.warm, 1);
        assert_eq!(view.seats.len(), 1);
        let later_bucket = vec![
            checkin("a", "a-phone", 0, 1, 0),
            checkin("a", "a-tablet", 2, 1, 1),
        ];
        let view = view_at(&later_bucket, 2 * BUCKET_TICKS);
        assert_eq!(view.warm, 1);
        assert_eq!(view.seats.len(), 1);
        assert_eq!(
            view.seats[0].warm_end,
            Some(2 * BUCKET_TICKS + WARM_MAX_TICKS)
        );
    }

    #[test]
    fn frozen_deadlines_survive_a_join_flood() {
        let mut facts = vec![checkin("first", "first-phone", 0, 1, 0)];
        let first_end = WARM_MAX_TICKS;
        for i in 1..200u64 {
            facts.push(checkin(&format!("m{i:03}"), "phone", i, 200, i));
        }
        let before = view_at(&facts, 0);
        let first = before.seats.iter().find(|s| s.member == "first").unwrap();
        assert_eq!(first.warm_end, Some(first_end));
        let during = view_at(&facts, 100 * BUCKET_TICKS);
        let first = during.seats.iter().find(|s| s.member == "first").unwrap();
        assert_eq!(first.warm_end, Some(first_end));
        assert_eq!(first.state, Seat::Warm);
    }

    #[test]
    fn growth_thresholds_need_no_consent() {
        assert_eq!(next_level(RoomLevel::Gone, 2), RoomLevel::Personal);
        assert_eq!(next_level(RoomLevel::Personal, 3), RoomLevel::Circle);
        assert_eq!(next_level(RoomLevel::Circle, 12), RoomLevel::Circle);
        assert_eq!(next_level(RoomLevel::Circle, 13), RoomLevel::Ingroup);
        assert_eq!(next_level(RoomLevel::Ingroup, 42), RoomLevel::Ingroup);
        assert_eq!(next_level(RoomLevel::Ingroup, 43), RoomLevel::Public);
        assert_eq!(next_level(RoomLevel::Circle, 43), RoomLevel::Public);
    }

    #[test]
    fn shrink_thresholds_hold_with_hysteresis() {
        assert_eq!(next_level(RoomLevel::Public, 42), RoomLevel::Public);
        assert_eq!(next_level(RoomLevel::Public, 37), RoomLevel::Public);
        assert_eq!(next_level(RoomLevel::Public, 36), RoomLevel::Ingroup);
        assert_eq!(next_level(RoomLevel::Public, 11), RoomLevel::Ingroup);
        assert_eq!(next_level(RoomLevel::Public, 10), RoomLevel::Circle);
        assert_eq!(next_level(RoomLevel::Ingroup, 12), RoomLevel::Ingroup);
        assert_eq!(next_level(RoomLevel::Ingroup, 11), RoomLevel::Ingroup);
        assert_eq!(next_level(RoomLevel::Ingroup, 10), RoomLevel::Circle);
        assert_eq!(next_level(RoomLevel::Ingroup, 3), RoomLevel::Circle);
        assert_eq!(next_level(RoomLevel::Circle, 2), RoomLevel::Personal);
        assert_eq!(next_level(RoomLevel::Personal, 1), RoomLevel::Alone);
        assert_eq!(next_level(RoomLevel::Alone, 0), RoomLevel::Gone);
        assert_eq!(next_level(RoomLevel::Public, 0), RoomLevel::Gone);
    }

    #[test]
    fn public_43_contracts_seat_by_seat() {
        let mut facts = Vec::new();
        for i in 0..43u64 {
            facts.push(checkin(&format!("m{i:02}"), "phone", i, i.max(1), i));
        }
        let probe = view_at(&facts, 10_000_000);
        let mut ends: Vec<u64> = probe.seats.iter().filter_map(|s| s.warm_end).collect();
        ends.sort_unstable();
        assert_eq!(ends.len(), 43);
        // Sweep every distinct end tick; equal ends fall out together.
        let mut distinct = ends.clone();
        distinct.dedup();
        let warm_before = |t: u64| ends.iter().filter(|e| **e >= t).count() as u64;
        let warm_at = |t: u64| ends.iter().filter(|e| **e > t).count() as u64;
        let mut level = RoomLevel::Public;
        let mut decided_at = 0u64;
        for (j, end) in distinct.iter().enumerate() {
            // All visits started long before any end, so the count is exact.
            assert!(*end > 43 * BUCKET_TICKS);
            let before = view_at(&facts, end - 1);
            assert_eq!(before.warm, warm_before(*end));
            let at = view_at(&facts, *end);
            assert_eq!(at.warm, warm_at(*end));
            level = next_level(level, at.warm);
            if at.warm > SHRINK_PUBLIC {
                assert_eq!(level, RoomLevel::Public, "W = {} stays public", at.warm);
            } else if level == RoomLevel::Ingroup && decided_at == 0 {
                decided_at = *end;
                let fallen = ends.iter().filter(|e| **e <= *end).count();
                assert_eq!(at.warm, SHRINK_PUBLIC, "36 is ingroup");
                assert_eq!(fallen, 7, "the seventh end decides the listing input");
            }
            let _ = j;
        }
        assert_ne!(decided_at, 0);
        assert_eq!(level, RoomLevel::Gone);
    }

    #[test]
    fn quiet_night_keeps_a_public_room_public() {
        let mut facts = Vec::new();
        for i in 0..37u64 {
            facts.push(checkin(&format!("m{i:02}"), "phone", 0, i.max(1), i));
        }
        let night = view_at(&facts, BUCKET_TICKS);
        assert_eq!(night.warm, 37);
        assert_eq!(next_level(RoomLevel::Public, night.warm), RoomLevel::Public);
    }

    #[test]
    fn ingroup_hysteresis_then_automatic_regrowth() {
        assert_eq!(
            replay(RoomLevel::Ingroup, &[11, 10, 13]),
            RoomLevel::Ingroup,
            "10 makes it a circle, 13 grows it back automatically, no consent fork"
        );
        assert_eq!(next_level(RoomLevel::Ingroup, 10), RoomLevel::Circle);
        assert_eq!(next_level(RoomLevel::Circle, 13), RoomLevel::Ingroup);
    }

    #[test]
    fn last_member_leaving_ends_the_room() {
        let facts = vec![checkin("a", "a-phone", 0, 1, 0)];
        let e = WARM_MAX_TICKS;
        assert_eq!(view_at(&facts, e - 1).warm, 1);
        let gone = view_at(&facts, e + COOL_MAX_TICKS);
        assert_eq!(gone.warm, 0);
        assert_eq!(next_level(RoomLevel::Alone, gone.warm), RoomLevel::Gone);
    }

    #[test]
    fn stale_views_stay_historical() {
        let early = vec![checkin("a", "a-phone", 0, 1, 0)];
        let old_view = view_at(&early, 0);
        let mut late = early.clone();
        late.push(checkin("b", "b-phone", 5, 2, 1));
        assert_eq!(view_at(&late, 0), old_view);
        assert_eq!(view_at(&late, 0).warm, 1);
        assert_eq!(view_at(&late, 5 * BUCKET_TICKS).warm, 2);
        assert_eq!(
            view_at(&late, 0),
            old_view,
            "same inputs give the same answer"
        );
    }

    #[test]
    fn future_checkins_do_not_count_yet() {
        let facts = vec![
            checkin("a", "a-phone", 0, 1, 0),
            checkin("b", "b-phone", 10, 1, 1),
        ];
        assert_eq!(view_at(&facts, 0).warm, 1);
        assert_eq!(view_at(&facts, 10 * BUCKET_TICKS).warm, 2);
    }

    #[test]
    fn invalid_facts_are_refused() {
        let bad_member = CheckIn {
            member: String::new(),
            device: "phone".into(),
            bucket_start: 0,
            frozen_n: 1,
            seq: 0,
        };
        assert!(evaluate(&[bad_member], &BTreeSet::new(), &[], 0).is_err());
        let unaligned = CheckIn {
            member: "a".into(),
            device: "phone".into(),
            bucket_start: 7,
            frozen_n: 1,
            seq: 0,
        };
        assert!(evaluate(&[unaligned], &BTreeSet::new(), &[], 7).is_err());
        let zero_n = checkin("a", "phone", 0, 0, 0);
        assert!(evaluate(&[zero_n], &BTreeSet::new(), &[], 0).is_err());
    }

    #[test]
    fn leaving_empties_the_seat() {
        let facts = vec![checkin("a", "a-phone", 0, 1, 0)];
        let mut out = BTreeSet::new();
        out.insert("a".to_string());
        let view = evaluate(&facts, &out, &[], 0).unwrap();
        assert_eq!(view.seats[0].state, Seat::Free);
        assert_eq!(view.warm, 0);
        assert_eq!(view.seats[0].warm_end, None);
    }
}
