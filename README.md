# cgrp — Groups

Consent-driven group lifecycle for member devices. Implementation is in progress;
this repository does not yet provide production group authority.

## Scope

### Purpose

Manages group life cycle on the member device through size-based levels, consent forks with lineage, safety controls, and local suggestions, without group administrators.

### Owns

- Levels Circle 3–12, Ingroup 13–42, and Public room 43–100. Visibility only grows through a consent fork at 12/13 and at 42/43. An Opening room has 21 days to reach 43. Groups shrink toward privacy at 36 or below and at 10 or below. Seed rooms started by an administrator are exempt.
- Forks for adding members, exclusion, split, merge, and opening. Lineage is shown as one conversation, and members who do not move keep their group.
- Nine behaviour bands read from signed group settings.
- A group view showing the current level and what changes next.
- Local split and merge suggestions, a local activity ledger, and preparation of welcome and introduction receipts.
- Membership decisions for groups; the encrypted conversation itself is carried by Threads, and the member backend wires both together into one atomic checkpoint.

### Never

- Administrators, kicks, votes, or expulsion.
- Visibility increases without consent.
- Charging for joining, forking, merging, or splitting.
- A server-side roster or activity ledger, seat spending at launch, or buying, transferring, or converting seats.
- Cryptographic primitives, transport, storage, or an accounting ledger; those remain with their existing owners.

### States

Circle becomes Ingroup only through a consent fork, then moves through Opening to Public. Public returns to Ingroup at 36 or below, and Ingroup returns to Circle at 10 or below. The limit at launch is 100 members.

### Test obligations

- Consent is required at 12/13 and at 42/43; the opening timeout, shrinking at 36 and 10, and the seed-room exemption are verified.
- Every view shows the level and the next change; all nine bands apply without automatic privacy changes.
- Exit forks leave non-moving members in place; no group action spends Waves.
- Split and merge suggestions show banners with cooldowns; concurrent consent and checkpoint replay behave correctly.
- Welcome and introduction receipts respect the weekly cap and headroom, and disabled seats block all seat spending.
- Native and WebAssembly builds use identical test vectors, with full line and branch coverage, real round trips, injected delay, duplication, loss, cancellation, clock regression, corruption, and storage conflicts.
- Publication is atomic with durable acceptance before acknowledgement; unknown outcomes reconcile without repeating effects; communities stay isolated; inputs stay bounded; errors omit identifiers, plaintext, and secrets.

## Implementation choices

Use Rust collections for bounded state, Serde for owner checkpoint formats and
thiserror for bounded errors. Crypto and storage remain with their established
owners. No generic state-machine framework replaces the explicit transitions.

## Validation

Public CI resolves dependencies once, runs stable native and real wasm vectors,
and gates exact LLVM line and branch counts at 100%. Nightly is used only for
branch instrumentation. Coverage is incomplete until those gates pass.
Dependabot refreshes Cargo and Actions; no npm manifest exists yet.

See [the contract](docs/CONTRACT.md) and [coverage policy](docs/COVERAGE.md).
