# cgrp — Groups

Consent-driven group lifecycle for member devices. Implementation is in progress;
this repository does not yet provide production group authority.

## Scope

Own lifecycle, consent forks and lineage, behavior bands, local activity and
suggestions. Read current signed policy; use verified consent and atomic device
persistence ports. No administrators, kicks, server rosters, cryptographic
primitives, or accounting ledger. Group joins and forks never spend Waves.
Seats are reserved formats and remain disabled.

Circle, Ingroup, Opening and Public transitions feed Threads. Assembly owns
blind room ordering; Attend coordinates device participation. Keys, Guard,
Compression and the accounting owners retain their existing jobs.

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
