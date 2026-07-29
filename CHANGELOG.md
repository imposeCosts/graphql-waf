# Changelog

All notable changes to this project are documented in this file.

## [0.1.1] - 2026-07-29

### Added
- Extracted proxy logic out of `src/main.rs` into a proper `graphql_waf` library crate
  (`src/lib.rs` + `src/proxy.rs`), with `src/main.rs` reduced to a thin CLI/runtime bootstrap.
- Integration test suite for the proxy (`tests/proxy_integration.rs`).
- `dvga-like-server`: standalone `main.rs` entrypoint so it can run outside of the workspace
  example harness.
- Additional ModSecurity rules and a dedicated GoTestWAF-tuned ruleset
  (`rules/modsec-gotestwaf-100.conf`, expanded `rules/modsec-graphql.conf`), plus a
  `rules/wirefilter-graphql.example` starter expression.
- OWASP API-focused GoTestWAF test cases (BOLA, broken auth, excessive data exposure, resource
  consumption) under `gotestwaf-testcases/owasp-api/`.
- `k6/graphql_loadtest.js` load-test script for proxy performance measurement.
- `.github/dependabot.yml` for automated dependency updates, and an expanded
  `.github/workflows/release.yml` / `security.yml` (RustSec audit, cargo-deny, CodeQL, Semgrep,
  scheduled fuzzing).
- `deny.toml` for license and advisory enforcement via `cargo-deny`.

### Changed
- GraphQL security checks (`src/graphql_security.rs`) hardened further — additional structural
  validation logic (+25 lines in the latest pass) beyond the existing depth/alias/directive/cost
  limits.
- `Makefile` reworked with more targets for running the upstream test server, the WAF, and
  Semgrep.

### Removed
- Committed WAF evaluation reports (CSV/PDF) that had been checked into the repo under
  `gotestwaf-testcases/` are no longer tracked.
- `examples/verify_modsec_rules.rs` removed (superseded by the integration test suite).

### Fixed
- CI: `RustSec (cargo audit)` job no longer fails to build `cargo-audit` from source against a
  newer-than-supported `rustc`; it now installs a prebuilt binary via `taiki-e/install-action`.
- CI: `cargo-deny` no longer fails on the `Unicode-3.0`-licensed `icu_*`/`unicode-ident` transitive
  dependencies (added to the license allow-list) or on the unsound-but-unpatchable `failure` crate
  advisory (`RUSTSEC-2019-0036`, pulled in transitively via `wirefilter-engine`; ignored with
  justification in `deny.toml`).

## [0.1.0]

Initial tagged release.
