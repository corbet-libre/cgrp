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

Unresolved policy inputs: explicit band up/down transition vectors, split-fork
privacy threshold, canonical exclusion-fork cost key. No default resolves these
ambiguities. Anonymous room permits, verified restart/handover proofs and real
MLS/Link integration are external capabilities, never accepting placeholders.

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
