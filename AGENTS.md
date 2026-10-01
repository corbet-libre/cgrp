# Agent instructions

Write comments and documentation in English. Preserve README Scope and
`docs/CONTRACT.md`; changes of product intent require owner approval.

Search maintained upstream and existing owners before writing. No own crypto,
server roster, group administrators, expulsion, duplicate ledger, or raw UI
roster as authority. Use current signed policy and verified scoped capabilities.
Persist the checkpoint before publishing membership effects.

Use LGPL-compatible dependencies, semver ranges, and first-party Git branch main.
Keep one resolved revision per first-party crate in Cargo.lock. Never publish to
registries. Plain English commits, no AI attribution or private operational data.

No workstation Cargo, including fmt and metadata. GitHub Actions runs stable
format/clippy/native and actual wasm tests; nightly LLVM gates 100% reachable
line and branch coverage. Do not lower gates or replace real logic with mocks.
Expensive load tests use the established owned CI scheduler, never workstations.
