# graphql-waf
A modescurity + graphql WAF. Extendible and high speed written in rust.

## Architecture

`graphql-waf` is a `hyper`-based reverse proxy (`src/main.rs` is a thin CLI/runtime bootstrap;
the proxy logic lives in the `graphql_waf` library crate, `src/proxy.rs` + `src/graphql_security.rs`).
For each request in `audit`/`block` mode, `handle_request` (`src/proxy.rs`):

1. Buffers the request body once, up to `max_body_bytes` (bodies larger than that are rejected
   in `block` mode by default — see `reject_oversized_body` below — rather than forwarded uninspected).
2. Runs three independent detectors and ORs their results into a single block decision:
   - **GraphQL security** (`src/graphql_security.rs`): introspection detection, GraphQL-over-GET
     blocking, batch detection, and structural limits (depth/aliases/directives/cost/variables)
     computed via `graphql-parser`.
   - **Wirefilter** ([Cloudflare's `wirefilter`](https://github.com/cloudflare/wirefilter)):
     a small fixed field scheme (method/host/UA/content-type/path/query/authorization/XFF/x-real-ip)
     evaluated against a user-supplied expression.
   - **ModSecurity** via [`zentinel-modsec`](https://crates.io/crates/zentinel-modsec): full
     request/header/body inspection via a compiled ruleset.
3. In `off` mode, none of the above runs — the proxy streams the request straight through.
4. In `block` mode, any detector match returns `400` with `x-waf-blocked: true`. In `audit` mode,
   matches are only logged; the request always forwards.
5. On the response side, GraphQL error responses can have `"Did you mean ...?"` field-suggestion
   hints stripped, to avoid leaking schema information to scanners.

`dvga-like-server/` is a separate, deliberately-vulnerable GraphQL stress-test target (axum +
`async-graphql`) used to exercise the WAF's limits in local testing and the `k6`/GoTestWAF suites
under `k6/` and `gotestwaf-testcases/`.

## Build & Test

```bash
cargo build
cargo build --manifest-path dvga-like-server/Cargo.toml

cargo test
cargo test --manifest-path dvga-like-server/Cargo.toml

cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Or via the Makefile:

```bash
make fmt
make clippy
```

## Run

This is a **reverse-proxy WAF**: it listens on `--listen-host/--listen-port`, inspects requests using:

- **ModSecurity rules** via [`zentinel-modsec`](https://crates.io/crates/zentinel-modsec)
- **expression matching** via Cloudflare’s [`wirefilter`](https://github.com/cloudflare/wirefilter)

Then it either **forwards**, **audits**, or **blocks** the request.

### Download a release

Prebuilt Linux binaries (`amd64`/`arm64`) are published on the
[Releases](https://github.com/imposeCosts/graphql-waf/releases) page for every tagged version,
built by `.github/workflows/release.yml`. Each release includes `graphql-waf`,
`dvga-like-server` (the local test upstream), and a `SHA256SUMS.txt` to verify the download.

```bash
# pick the arch matching your machine
curl -fsSL -o graphql-waf \
  https://github.com/imposeCosts/graphql-waf/releases/latest/download/graphql-waf-linux-amd64
curl -fsSL -o SHA256SUMS.txt \
  https://github.com/imposeCosts/graphql-waf/releases/latest/download/SHA256SUMS.txt

sha256sum -c <(grep graphql-waf-linux-amd64 SHA256SUMS.txt)
chmod +x graphql-waf
```

Then run it against a config file (see `waf.example.toml` and the
[Configuration reference](#configuration-reference) below for all available options):

```bash
./graphql-waf --config waf.example.toml
```

CLI flags and environment variables override the config file, so you can layer overrides on top
of a base config, e.g.:

```bash
./graphql-waf --config waf.example.toml --listen-port 8443 --mode audit
```

## Static analysis (Semgrep)

Install and run Semgrep:

```bash
make semgrep-install
make semgrep
```

## Local upstream server (for proxy perf tests)

This repo includes a small “DVGA-like” GraphQL upstream you can run locally. It’s designed to generate **heavy query shapes** (deep nesting, big lists, CPU-ish work) so you can measure proxy overhead and tune WAF behavior.

### Start upstream

```bash
make upstream-run
```

- GraphQL endpoint: `http://127.0.0.1:4000/graphql`
- Playground UI: `http://127.0.0.1:4000/graphiql`

### Start WAF in front of it

```bash
make waf-run ARGS='--listen-host 127.0.0.1 --listen-port 8080 --mode audit'
```

Then point clients at:

- `http://127.0.0.1:8080/graphql` (proxied through the WAF)

### Sample queries (good for perf comparisons)

Baseline:

```graphql
query { ping }
```

Deep nesting (depth/recursion stress):

```graphql
query {
  nestedNode(depth: 60) {
    id
    name
    depth
    child { id name depth child { id name depth } }
  }
}
```

Large payload (serialization/bandwidth stress):

```graphql
query { bigList(size: 5000) { id name } }
```

CPU-ish work (server-side compute stress):

```graphql
query { fib(n: 42) }
```

### Example

```bash
cargo run -- \
  --config waf.example.toml \
  --listen-host 127.0.0.1 \
  --listen-port 8080 \
  --upstream http://127.0.0.1:4000 \
  --mode block \
  --graphql-security \
  --block-introspection \
  --modsec-rules rules/modsec-example.conf \
  --wirefilter 'http.method == "POST" && http.request.uri.path contains "graphql"'
```

### Modes

- **`off`**: no inspection, pure reverse proxy
- **`audit`**: log decisions (never blocks)
- **`block`**: blocks when ModSecurity triggers OR Wirefilter matches

### Wirefilter fields available

The built-in scheme includes:

- `http.method`
- `http.host`
- `http.user_agent`
- `http.content_type`
- `http.request.uri.path`
- `http.request.uri.query`
- `http.request.headers.authorization`
- `http.request.headers.x_forwarded_for`
- `http.request.headers.x_real_ip`

## Configuration reference

Every option below can be set via TOML config (`--config path.toml`, see `waf.example.toml`),
CLI flag, or environment variable; CLI/env always override the config file. See `src/config.rs`
for the authoritative field list.

### `[waf]`

| TOML key | CLI flag / env | Default | Effect |
| --- | --- | --- | --- |
| `listen_host` | `--listen-host` / `WAF_HOST` | `127.0.0.1` | Bind address for the proxy listener. |
| `listen_port` | `--listen-port` / `WAF_PORT` | `8080` | Bind port for the proxy listener. |
| `upstream` | `--upstream` / `WAF_UPSTREAM` | *(required)* | Upstream base URL to forward requests to. |
| `mode` | `--mode` / `WAF_MODE` | `block` | `off` (pure passthrough), `audit` (log only, never blocks), `block`. |
| `modsec_rules` | `--modsec-rules` / `WAF_MODSEC_RULES` | none | ModSecurity rule file(s)/glob(s) to compile and enforce. |
| `wirefilter` | `--wirefilter` / `WAF_WIREFILTER` | none | Wirefilter expression; a match contributes to the block decision. |
| `max_body_bytes` | `--max-body-bytes` / `WAF_MAX_BODY_BYTES` | `1048576` (1 MiB) | Maximum request body size actually inspected. |
| `reject_oversized_body` | `--reject-oversized-body` / `WAF_REJECT_OVERSIZED_BODY` | `true` | If true, a body over `max_body_bytes` is blocked in `block` mode instead of forwarded uninspected. Set `false` to restore the old permissive behavior for deployments with legitimate oversized traffic. |
| `worker_threads` | `--worker-threads` / `WAF_WORKER_THREADS` | `2` | Tokio runtime worker threads; must be `>= 1`. |

### `[graphql]`

| TOML key | CLI flag / env | Default | Effect |
| --- | --- | --- | --- |
| `enabled` | `--graphql-security` / `WAF_GRAPHQL_SECURITY` | `true` | Master switch for all GraphQL-specific checks below. |
| `block_non_graphql_paths` | `--graphql-block-non-graphql-paths` / `WAF_GRAPHQL_BLOCK_NON_GRAPHQL_PATHS` | `false` | Block requests not targeting `/graphql` or `/graphiql` (useful when the proxy should expose only GraphQL). |
| `block_introspection` | `--block-introspection` / `WAF_BLOCK_INTROSPECTION` | `false` | Block queries containing `__schema`/`__type`. |
| `allow_introspection_header` | `--graphql-allow-introspection-header` / `WAF_GRAPHQL_ALLOW_INTROSPECTION_HEADER` | none | If this header is present on the request, introspection blocking is bypassed (e.g. for GoTestWAF). |
| `allow_get` | `--graphql-allow-get` / `WAF_GRAPHQL_ALLOW_GET` | `false` | Allow GraphQL-over-GET requests. |
| `block_invalid_query` | `--graphql-block-invalid` / `WAF_GRAPHQL_BLOCK_INVALID` | `true` | Block requests that look like GraphQL but fail to parse. |
| `block_batch` | `--block-graphql-batch` / `WAF_BLOCK_GRAPHQL_BATCH` | `false` | Block batched JSON requests (array of operations). |
| `max_query_bytes` | `--graphql-max-query-bytes` / `WAF_GRAPHQL_MAX_QUERY_BYTES` | unset (unlimited) | Maximum query document size. |
| `max_depth` | `--graphql-max-depth` / `WAF_GRAPHQL_MAX_DEPTH` | unset (unlimited) | Maximum selection-set nesting depth. |
| `max_aliases` | `--graphql-max-aliases` / `WAF_GRAPHQL_MAX_ALIASES` | unset (unlimited) | Maximum number of aliased fields. |
| `max_directives` | `--graphql-max-directives` / `WAF_GRAPHQL_MAX_DIRECTIVES` | unset (unlimited) | Maximum number of directives used. |
| `max_cost` | `--graphql-max-cost` / `WAF_GRAPHQL_MAX_COST` | unset (unlimited) | Maximum computed query cost (see cost model below). |
| `cost_scalar_cost` | `--graphql-cost-scalar-cost` / `WAF_GRAPHQL_COST_SCALAR_COST` | `1` | Cost of a scalar leaf field. |
| `cost_object_cost` | `--graphql-cost-object-cost` / `WAF_GRAPHQL_COST_OBJECT_COST` | `2` | Cost of a field with a sub-selection. |
| `cost_depth_cost_factor` | `--graphql-cost-depth-cost-factor` / `WAF_GRAPHQL_COST_DEPTH_FACTOR` | `1.5` | Multiplier applied per nesting level. |
| `cost_flatten_fragments` | `--graphql-cost-flatten-fragments` / `WAF_GRAPHQL_COST_FLATTEN_FRAGMENTS` | `false` | Treat fragments as inline for cost purposes. |
| `cost_ignore_introspection` | `--graphql-cost-ignore-introspection` / `WAF_GRAPHQL_COST_IGNORE_INTROSPECTION` | `true` | Exclude `__schema`/`__type` fields from the cost total. |
| `cost_fragment_recursion_cost` | `--graphql-cost-fragment-recursion-cost` / `WAF_GRAPHQL_COST_FRAGMENT_RECURSION_COST` | `1000` | Extra cost added when a fragment spread recurses (cycle guard). |
| `max_variables_bytes` | `--graphql-max-variables-bytes` / `WAF_GRAPHQL_MAX_VARIABLES_BYTES` | unset (unlimited) | Maximum size of the `variables` JSON value. |
| `max_variables_depth` | `--graphql-max-variables-depth` / `WAF_GRAPHQL_MAX_VARIABLES_DEPTH` | unset (unlimited) | Maximum nesting depth of the `variables` JSON value. |
| `max_variables_keys` | `--graphql-max-variables-keys` / `WAF_GRAPHQL_MAX_VARIABLES_KEYS` | unset (unlimited) | Maximum total object keys in the `variables` JSON value. |
| `max_variables_array_len` | `--graphql-max-variables-array-len` / `WAF_GRAPHQL_MAX_VARIABLES_ARRAY_LEN` | unset (unlimited) | Maximum length of any array inside `variables`. |
| `block_field_suggestions` | `--graphql-block-field-suggestions` / `WAF_GRAPHQL_BLOCK_FIELD_SUGGESTIONS` | `true` | Strip `"Did you mean ...?"` hints from JSON error responses. |
| `max_response_bytes` | `--graphql-max-response-bytes` / `WAF_GRAPHQL_MAX_RESPONSE_BYTES` | `262144` (256 KiB) | Maximum response body buffered for suggestion stripping. |

The `max_*` limits above are disabled (unenforced) unless explicitly set — see `waf.example.toml`
for a starting point with recommended values.

