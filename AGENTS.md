# cgrp agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p cgrp` — native vectors, green:
  lib `3 passed`, vectors `35 passed`, exit 0
- `~/agents/scratch/cbuild <lane> clippy -p cgrp --all-targets -- -D warnings` — must be clean
- `~/agents/scratch/cbuild <lane> fmt -p cgrp -- --check` — must be clean
- Full gate (wasm vectors, nightly 100% reachable line+branch coverage) in CI: `.ci/verify.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test in `tests/cases/` unless noted):
- No admins, kicks, or expulsion; only self-`Leave` and consent `Exclusion` forks
  -> `lifecycle.rs::exit_forks_preserve_nonmovers_and_cooldowns`
- Counts are verified member sets; a UI roster is never authority
  -> `adversarial.rs::creations_and_private_joins_require_real_consent_and_vouches`
- Hysteresis thresholds are signed settings with enforced order (public 43/36,
  ingroup 13/10, cap 256)
  -> `adversarial.rs::invalid_policy_never_becomes_authority`, `lifecycle.rs::privacy_forks_timeout_and_shrink`
- Listing entry valid exactly while public by the warm count (expiry = computed
  warm-count crossing below 36, monotone counter); key rotates immediately on
  churn/fork; a stale key can only withdraw, never sign live or adopt fresh
  -> `listing.rs::entries_are_deterministic_monotone_and_bounded`
- No own crypto/compression/ledger; seats disabled (`seats.enabled` refused);
  accounting grants are foreign
  -> `local.rs::receipt_preparation_never_forges_an_accounting_grant`
- Effects publish only after `Applied`; `Conflict`/`Unknown` yield nothing;
  exact-predecessor `check_base`
  -> `lifecycle.rs::consent_and_atomic_publication_refuse_replay_and_corruption`
- Pending work bounded by `min(policy, consents, opening)`; waiting never extends timestamps
  -> `publication.rs::pending_opening_cannot_publish_across_its_original_deadline`
- Canonical store `snapshot.v1` (Postcard), bounded decode, `MAX_MEMBERS=256`
  -> `publication.rs::canonical_snapshot_uses_the_real_encrypted_store`

Pointers: `src/lifecycle.rs`, `src/policy.rs`, `src/listing.rs`,
`docs/CONTRACT.md`, `docs/COVERAGE.md`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
LGPL-compatible deps only, no GPL/AGPL; first-party follow `main`; no registry publication.
