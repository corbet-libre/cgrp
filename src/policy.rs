use crate::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Notification {
    EveryMessage,
    QuietHours,
    SilentReactions,
    MentionsReplies,
    MentionsRepliesDigest,
    MentionsDigest,
    MentionsDaily,
    ContactsWeekly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Band {
    pub lower: u16,
    /// Explicit signed transition vectors; canonical defaults enter at the lower
    /// edge and leave two members below it.
    pub enter_up: u16,
    pub leave_down: u16,
    pub notification: Notification,
    pub posts_per_hour: u16,
    pub burst: u16,
    pub vouches: u16,
    pub history_seconds: u64,
    pub history_messages: u16,
    pub joins_per_hour: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SeatFormats {
    pub enabled: bool,
    pub refill_per_day: f64,
    pub capacity: f64,
    pub initial: f64,
    pub minimum: f64,
    pub small: f64,
    pub large: f64,
    pub low: u16,
    pub high: u16,
    pub tau: f64,
    pub epoch_days: u16,
    pub quantum: f64,
    pub warning_days: u16,
}

/// Technical ceiling of a group's membership (2^8). The user-facing limit of a
/// public room is 250 (`Policy::cap`); the six seats of cushion absorb joins in
/// flight, pending leaves and fork overlaps. Hidden groups stay at `ingroup_max`.
pub const MAX_MEMBERS: u16 = 256;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub epoch: u64,
    pub valid_until: u64,
    pub cap: u16,
    pub circle_max: u16,
    pub ingroup_max: u16,
    pub shrink_public: u16,
    pub shrink_ingroup: u16,
    pub open_seconds: u64,
    pub fork_cooldown: u64,
    pub retarget_cooldown: u64,
    pub listing_wait: u64,
    /// Minimum size for a newly split public fork; canonical policy is 43,
    /// separately from the existing-room shrink threshold of 36.
    pub split_public_min: u16,
    pub bands: [Band; 9],
    pub seats: SeatFormats,
    pub suggest_at: u16,
    pub pressure_at: u16,
    pub modularity: f64,
    pub overlap: f64,
    pub suggestion_cooldown: u64,
    pub decline_cooldown: u64,
    pub reciprocity_enabled: bool,
    /// Quarter-Wave units avoid float accounting. The accounting owner grants.
    pub welcome_quarters: u16,
    pub introduction_quarters: u16,
    pub week_cap_quarters: u16,
}

impl Policy {
    pub fn validate(&self, now: u64) -> Result<()> {
        if self.valid_until <= now || self.seats.enabled {
            return Err(Error::Policy);
        }
        // Growth thresholds are rulebook settings. Defaults are 12 / 42 / 36 / 10;
        // the bounds keep the ordering and the privacy minimum (a circle holds
        // at least three) so a test community may run small values.
        if self.cap > MAX_MEMBERS
            || !(3..=12).contains(&self.circle_max)
            || !(self.circle_max + 1..=42).contains(&self.ingroup_max)
            || !(self.circle_max + 1..=self.ingroup_max).contains(&self.shrink_public)
            || !(2..self.circle_max).contains(&self.shrink_ingroup)
            || self.cap <= self.ingroup_max
            || !(self.shrink_public + 1..=self.ingroup_max + 1).contains(&self.split_public_min)
        {
            return Err(Error::Policy);
        }
        let finite = [
            self.seats.refill_per_day,
            self.seats.capacity,
            self.seats.initial,
            self.seats.minimum,
            self.seats.small,
            self.seats.large,
            self.seats.tau,
            self.seats.quantum,
            self.modularity,
            self.overlap,
        ];
        if finite.iter().any(|x| !x.is_finite() || *x < 0.0)
            || self.seats.low <= 2
            || self.seats.high >= self.cap
            || self.seats.low > self.seats.high
            || self.modularity > 1.0
            || self.overlap > 1.0
        {
            return Err(Error::Policy);
        }
        let mut previous_lower = 0;
        for band in self.bands.iter() {
            let ordered = band.lower > previous_lower;
            previous_lower = band.lower;
            if !ordered
                || band.lower < 3
                || band.lower > self.cap
                || band.enter_up < band.lower
                || band.leave_down >= band.enter_up
                || band.posts_per_hour == 0
                || band.burst == 0
                || band.vouches > 2
            {
                return Err(Error::Policy);
            }
        }
        Ok(())
    }

    pub fn band(&self, size: u16, previous: usize) -> Result<usize> {
        if previous >= self.bands.len() {
            return Err(Error::Invalid);
        }
        let mut index = previous;
        while index + 1 < self.bands.len() && size >= self.bands[index + 1].enter_up {
            index += 1;
        }
        while index > 0 && size <= self.bands[index].leave_down {
            index -= 1;
        }
        Ok(index)
    }

    pub fn seat_weight(&self, size: u16) -> f64 {
        let s = &self.seats;
        let low = f64::from(s.low.saturating_sub(size)) / f64::from(s.low - 2);
        let high = f64::from(size.saturating_sub(s.high)) / f64::from(self.cap - s.high);
        s.minimum + s.small * low * low + s.large * high * high
    }
}

/// Trusted policy adapter: authenticate exact signed crbk settings, origin,
/// revision, epoch and expiry. Missing required keys must refuse, not default.
pub trait PolicySource {
    fn current(&self, community: &str, now: u64) -> Result<Policy>;
}
