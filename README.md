# graphql-waf
A modescurity + graphql WAF. Extendible and high speed written in rust.

## Run

This is a **reverse-proxy WAF**: it listens on `--listen-host/--listen-port`, inspects requests using:

- **ModSecurity rules** via [`zentinel-modsec`](https://crates.io/crates/zentinel-modsec)
- **expression matching** via Cloudflare’s [`wirefilter`](https://github.com/cloudflare/wirefilter)

Then it either **forwards**, **audits**, or **blocks** the request.

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

