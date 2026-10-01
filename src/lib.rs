//! Device-local group lifecycle, with authority and durable publication supplied by ports.
#![forbid(unsafe_code)]

mod activity;
mod lifecycle;
mod policy;
mod receipts;
mod suggestions;

pub use activity::*;
pub use lifecycle::*;
pub use policy::*;
pub use receipts::*;
pub use suggestions::*;

/// Bounded refusal codes never contain member data or upstream errors.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, thiserror::Error, serde::Serialize, schemars::JsonSchema,
)]
pub enum Error {
    #[error("invalid input")]
    Invalid,
    #[error("policy unavailable or unsupported")]
    Policy,
    #[error("authority unavailable or refused")]
    Authority,
    #[error("revision conflict")]
    Conflict,
    #[error("storage outcome requires reconciliation")]
    Reconcile,
    #[error("resource limit reached")]
    Capacity,
    #[error("clock regression")]
    Clock,
    #[error("required integration unavailable")]
    Unavailable,
}

pub type Result<T> = std::result::Result<T, Error>;
pub type Id = [u8; 32];
pub const DAY: u64 = 86_400;

pub(crate) fn encode(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::Invalid)
}
