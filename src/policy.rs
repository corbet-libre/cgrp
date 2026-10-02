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
        if self.cap > 100
            || self.circle_max != 12
            || self.ingroup_max != 42
            || self.shrink_public != 36
            || self.shrink_ingroup != 10
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
        let edges = [3, 6, 9, 13, 20, 30, 43, 60, 80];
        for (i, band) in self.bands.iter().enumerate() {
            if band.lower != edges[i]
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
