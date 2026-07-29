# Contributing

## Build & test

```bash
cargo build
cargo build --manifest-path dvga-like-server/Cargo.toml

make test          # cargo test for both crates
make fmt            # cargo fmt (root crate)
make clippy          # cargo clippy -- -D warnings (root crate)
```

CI (`.github/workflows/ci.yml`) runs `fmt`, `clippy`, `test`, and `build` for **both** the root
`graphql-waf` crate and `dvga-like-server/` — make sure both pass locally before opening a PR.

A `rust-toolchain.toml` pins the exact Rust version used in CI; `rustup` will pick it up
automatically.

## Local end-to-end run

```bash
make upstream-run                                          # starts dvga-like-server on :4000
make waf-run ARGS='--listen-host 127.0.0.1 --listen-port 8080 --mode audit'
```

See the README's "Run" section for sample queries and the full configuration reference.

## Security tooling

- `cargo audit` (RustSec advisories) and `cargo-deny` (license/advisory/source policy in
  `deny.toml`) run in CI on every push/PR and on a weekly schedule.
- Semgrep (`.semgrep.yml` plus the `p/rust` and `p/security-audit` rulesets) runs in CI; run it
  locally first with `make semgrep-install && make semgrep`.
- CodeQL runs weekly and on every push/PR to `main`.
- Fuzz targets under `fuzz/` (`graphql_security`, `wirefilter_expr`) exercise the untrusted-input
  parsing paths -- the GraphQL query/variables extraction + introspection scanner, and wirefilter
  expression parsing. Requires nightly Rust and `cargo-fuzz`:

  ```bash
  cargo install cargo-fuzz
  rustup toolchain install nightly
  cargo +nightly fuzz run graphql_security -- -max_total_time=60
  cargo +nightly fuzz run wirefilter_expr -- -max_total_time=60
  ```

  These run on a weekly schedule in CI (`.github/workflows/security.yml`), not per-PR, since
  fuzzing runs are slow/flaky as a per-commit gate.

## A note on `rules/` and `gotestwaf-testcases/`

The ModSecurity rule files under `rules/` are **not** all production-ready defaults:

- `rules/modsec-example.conf` and `rules/modsec-rest-tighten.conf` are reasonable starting
  points.
- `rules/modsec-gotestwaf-100.conf` is explicitly tuned to raise scores against the GoTestWAF
  benchmark (see the comment at the top of that file) and will produce many false positives on
  real traffic. Don't copy it into a production config without understanding what it does.
- `rules/wirefilter.example` and `rules/wirefilter-graphql.example` are example expressions to
  adapt, not a ready-to-use policy.

`gotestwaf-testcases/owasp-api/` contains payloads used to drive the `make gotestwaf-scan-*`
targets against a running WAF instance — see the Makefile for the full list of scan targets.

## Pull requests

- Keep PRs focused; a bug fix doesn't need unrelated cleanup bundled in.
- Add or update tests for any behavior change (see `src/graphql_security.rs` and `src/proxy.rs`
  for the existing unit-test style, and `tests/proxy_integration.rs` for integration-test style).
- If a change affects a documented config field, update the "Configuration reference" table in
  `README.md` and `waf.example.toml` together so they don't drift.
