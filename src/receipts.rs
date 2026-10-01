use crate::{DAY, Error, Id, Policy, Result, encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum ReceiptKind {
    Welcome,
    Introduction,
}

/// Private receipt preparation only. Recipient signatures and zero-knowledge
/// grant submission belong to the accounting owner; never send this to cfrm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptRequest {
    pub operation: Id,
    pub community: String,
    pub group: Id,
    pub beneficiary: String,
    pub recipients: BTreeSet<String>,
    pub kind: ReceiptKind,
    pub occurred_at: u64,
    pub deadline: u64,
    pub policy_epoch: u64,
}

/// Common context supplied by the device, never sent to the forum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptContext {
    pub operation: Id,
    pub community: String,
    pub group: Id,
    pub beneficiary: String,
}

impl ReceiptRequest {
    pub fn welcome(
        context: ReceiptContext,
        newcomer: String,
        joined_at: u64,
        first_reply: u64,
        policy: &Policy,
    ) -> Result<Self> {
        let ReceiptContext {
            operation,
            community,
            group,
            beneficiary,
        } = context;
        if first_reply < joined_at || first_reply - joined_at > 3 * DAY || newcomer == beneficiary {
            return Err(Error::Invalid);
        }
        Ok(Self {
            operation,
            community,
            group,
            beneficiary,
            recipients: BTreeSet::from([newcomer]),
            kind: ReceiptKind::Welcome,
            occurred_at: first_reply,
            deadline: joined_at.saturating_add(3 * DAY),
            policy_epoch: policy.epoch,
        })
    }
    pub fn introduction(
        context: ReceiptContext,
        recipients: BTreeSet<String>,
        introduced_at: u64,
        answers: [u64; 2],
        policy: &Policy,
    ) -> Result<Self> {
        let ReceiptContext {
            operation,
            community,
            group,
            beneficiary,
        } = context;
        if recipients.len() != 2
            || recipients.contains(&beneficiary)
            || answers
                .iter()
                .any(|at| *at < introduced_at || at - introduced_at > 14 * DAY)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            operation,
            community,
            group,
            beneficiary,
            recipients,
            kind: ReceiptKind::Introduction,
            occurred_at: answers[0].max(answers[1]),
            deadline: introduced_at.saturating_add(14 * DAY),
            policy_epoch: policy.epoch,
        })
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        encode(&("cgrp.receipt.v1", self))
    }
}

/// This port is implemented by the accounting holder/issuer, not by Groups.
/// It must verify recipient receipts and first-reply/answered-contact evidence,
/// enforce global weekly credit and headroom, and adopt signed acceptance once.
/// An unavailable proof or grant endpoint must return Unavailable.
pub trait Accounting {
    type Acceptance;
    fn grant(
        &mut self,
        request: &ReceiptRequest,
        recipient_receipts: &[Vec<u8>],
        policy: &Policy,
    ) -> Result<Self::Acceptance>;
}

pub fn request_credit<A: Accounting>(
    accounting: &mut A,
    request: &ReceiptRequest,
    recipient_receipts: &[Vec<u8>],
    policy: &Policy,
    now: u64,
) -> Result<A::Acceptance> {
    policy.validate(now)?;
    if !policy.reciprocity_enabled
        || request.policy_epoch != policy.epoch
        || now < request.occurred_at
        || now > request.deadline
        || recipient_receipts.len() != request.recipients.len()
    {
        return Err(Error::Authority);
    }
    accounting.grant(request, recipient_receipts, policy)
}
