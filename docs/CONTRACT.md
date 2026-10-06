# Contract

The Groups device library owns Circle / Ingroup / Opening / Public lifecycle,
consent-only privacy increases, automatic privacy-increasing shrink, fork
lineage, all nine behavior bands, local suggestions and activity, and receipt
preparation. Group creation and membership require verified consent; a UI roster
is never authority. State is checkpointed through device persistence before
membership effects reach Threads.

The launch cap is 100. Opening expires after 21 days. Public shrinks at 36 and
Ingroup at 10; authenticated public seeds are exempt. No group admins or kicks.
Joining, adding, merging, splitting and exclusion forks never cost Waves.
Accounting grants belong to the accounting owners. Seat formats are disabled.

Policy comes from authenticated settings. The canonical curve enters each band
at its lower edge and leaves it two members below that edge (20 up, 18 down).
A newly split public fork needs at least 43 members; the automatic shrink of an
existing public room remains 36. Exclusion-fork cost is groups.fork_cost_sp (2
seat points), dormant while seats.enabled is false. These policy values do not
authorize a group or replace current signed policy and consent checks.
Anonymous room permits, verified restart/handover proofs and real MLS/Link
integration remain external capabilities, never accepting placeholders.

## Implemented API and integration limits

`prepare(Snapshot, Request, PolicySource, Authority, now, max_groups)` verifies
policy/consent bindings and prepares an atomic candidate. `Candidate::persist`
returns `CommittedEffect` capabilities only after the checkpoint/outbox reports
Applied. Conflict and unknown writes return no effects. The composition root
must reconcile an unknown write from authenticated storage before retrying.
`CommittedEffect` has no public constructor or deserializer; Threads consumes
its `community()` and `event()` with replay fencing on revision/group/epoch.
The serializable `Effect` alone is not authority.

`PolicySource` must authenticate the current exact crbk snapshot; `Authority`
must repeat Guard, current device authority, consent signature and contact checks.
The signed fixture adapter exercises real cryptography but is not a production
Guard/G3 or Contacts integration. Those adapters remain required. Receipt
preparation returns no balance; `Accounting` must supply real accepted grants,
weekly cap and headroom. Tests deliberately refuse the unavailable grant path.
Compression belongs to cprz before Padme and encryption at checkpoint ownership;
Groups neither compresses nor encrypts its own parallel store.

Groups preparation carries the exact authenticated policy band and expiry in
`PreparedEffect::policy_band()` and `policy_valid_until()`. The capability binds
these to its community, group and candidate revision; a caller cannot replace
its band. Threads must recheck time/current authority before publication.
`Persistence::commit` returns `CommitFuture`; `Candidate::persist` is async and
releases committed capabilities only after the shared transaction reports
`Applied`. Browser adapters must await IndexedDB, never block the browser.

Pending work uses `PreparedEffect::valid_until()`, the minimum of the original
policy and every verified signed consent expiry. `Candidate::persist(store,
now).await` refuses expired or regressed preparation before writing. Shared
transaction adapters must revalidate current authority before committing; an
old preparation is not a lease. Committed outbox delivery remains distinct.

The canonical encrypted cwst record is owner `cgrp`, key `snapshot.v1`, with
Postcard 1 serde encoding of `Snapshot`. JSON cannot encode this snapshot's
binary map keys. Decode only authenticated device-storage records; arbitrary
frontend bytes and a deserialized DTO are never membership authority.

`Snapshot::load(community, &cwst::Store)` owns that canonical decode and refuses
corrupt or foreign state; absence alone yields an initial empty view.
`Candidate::revalidate(policy, authority, now)` repeats the original signed
policy, every consent, required contact and seed authorization against fresh
authority after asynchronous work. It retains the original request/base and
command times; no opening, cooldown or join timestamp is extended. Exact policy
changes or a timed opening transition invalidate pending publication. Threads
invokes this method after custody checks and before the combined Store commit.

Consent v2 binds the original operation, member, community, policy epoch,
visibility, expiry and command digest. The command digest binds actor, complete
command, sorted exact per-group parent commitments and the shared `effective_at`
time. It never signs a device's local journal revision. Each candidate instead
retains its complete local predecessor for the Store CAS. Commands change only
their target; unrelated groups and nonmover parents remain intact. Tick owns
local timed transitions. Per-group revisions advance only when that group changes.

`GroupState` is a bounded versioned canonical encoding using the existing Groups
encoder and Keys hash. `PreparedEffect::group_state()` binds it to genuine
preparation. `Snapshot::group_state` and `parent_references` are metadata, never
import capabilities. Old v1 consent and checkpoints without per-group revisions
are refused; no signed-field rewriting or inferred migration is allowed.
Threads binds the commitment in maintained MLS GroupContext. A newcomer still
requires independently authenticated invitation/selected-room evidence plus
verified MLS import; decoding GroupState cannot populate a local parent.
