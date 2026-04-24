use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes as HttpBodyBytes;
use clap::{Parser, ValueEnum};
use glob::glob;
use http::{header, HeaderMap, HeaderValue, Request, Response, StatusCode, Uri};
use hyper::{
    body::to_bytes,
    client::{Client, HttpConnector},
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Server,
};
use hyper_tls::HttpsConnector;
use tracing::{error, info, warn};
use url::Url;
use wirefilter::{ExecutionContext, Scheme};
use zentinel_modsec::{CompiledRuleset, ModSecurity};

mod config;
mod graphql_security;

use config::load_toml_config;
use graphql_security::{
    evaluate_graphql_security, looks_like_graphql_request, strip_graphql_field_suggestions,
    GraphqlSecurityConfig,
};

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum WafMode {
    Off,
    Audit,
    Block,
}

#[derive(Parser, Debug)]
#[command(
    name = "graphql-waf",
    about = "REST reverse-proxy WAF using zentinel-modsec + wirefilter"
)]
struct Cli {
    /// Optional path to a TOML config file (values here act as defaults; CLI/env override).
    #[arg(long, env = "WAF_CONFIG")]
    config: Option<PathBuf>,

    /// Disable all logging output (overrides RUST_LOG / default JSON logs).
    #[arg(long, env = "WAF_DISABLE_LOGGING", default_value_t = false)]
    disable_logging: bool,

    /// Tokio runtime worker threads (multi-thread scheduler).
    ///
    /// If not set, defaults to 2, or `waf.worker_threads` from config.
    #[arg(long, env = "WAF_WORKER_THREADS")]
    worker_threads: Option<usize>,

    /// Host/IP to bind the WAF listener to.
    #[arg(long, env = "WAF_HOST")]
    listen_host: Option<String>,

    /// Port to bind the WAF listener to.
    #[arg(long, env = "WAF_PORT")]
    listen_port: Option<u16>,

    /// Upstream base URL to forward requests to (example: http://127.0.0.1:4000).
    #[arg(long, env = "WAF_UPSTREAM")]
    upstream: Option<String>,

    /// WAF behavior.
    #[arg(long, env = "WAF_MODE", value_enum)]
    mode: Option<WafMode>,

    /// ModSecurity rules file(s). Can be repeated. Globs are supported by zentinel-modsec.
    #[arg(long, env = "WAF_MODSEC_RULES")]
    modsec_rules: Vec<String>,

    /// Wirefilter expression. If it evaluates to true, the request is considered "matched".
    /// In block mode, a match blocks; in audit mode, a match is logged.
    #[arg(long, env = "WAF_WIREFILTER")]
    wirefilter: Option<String>,

    /// Maximum request body bytes to inspect (and buffer before proxying).
    #[arg(long, env = "WAF_MAX_BODY_BYTES")]
    max_body_bytes: Option<usize>,

    /// GraphQL protection: block introspection queries (detects __schema/__type).
    ///
    /// - In `block` mode: blocks when matched.
    /// - In `audit` mode: logs when matched, but does not block.
    #[arg(
        long,
        env = "WAF_BLOCK_INTROSPECTION",
        default_missing_value = "true",
        num_args = 0..=1
    )]
    block_introspection: Option<bool>,

    /// Enable GraphQL security checks (introspection/limits/batch) for requests that look like GraphQL.
    #[arg(
        long,
        env = "WAF_GRAPHQL_SECURITY",
        default_missing_value = "true",
        num_args = 0..=1
    )]
    graphql_security: Option<bool>,

    /// If present on the request, bypass introspection blocking (useful for tools like GoTestWAF).
    #[arg(long, env = "WAF_GRAPHQL_ALLOW_INTROSPECTION_HEADER")]
    graphql_allow_introspection_header: Option<String>,

    /// GraphQL protection: block batched JSON requests (array of operations).
    #[arg(
        long,
        env = "WAF_BLOCK_GRAPHQL_BATCH",
        default_missing_value = "true",
        num_args = 0..=1
    )]
    block_graphql_batch: Option<bool>,

    /// GraphQL protection: block invalid GraphQL queries (parse failures) when a query is present.
    #[arg(
        long,
        env = "WAF_GRAPHQL_BLOCK_INVALID",
        default_missing_value = "true",
        num_args = 0..=1
    )]
    graphql_block_invalid: Option<bool>,

    /// GraphQL protection: allow GraphQL-over-GET requests.
    ///
    /// Default: false (GET is blocked when it carries a GraphQL operation).
    #[arg(
        long,
        env = "WAF_GRAPHQL_ALLOW_GET",
        default_missing_value = "true",
        num_args = 0..=1
    )]
    graphql_allow_get: Option<bool>,

    /// GraphQL protection: maximum query document bytes (after decoding/parsing).
    #[arg(long, env = "WAF_GRAPHQL_MAX_QUERY_BYTES")]
    graphql_max_query_bytes: Option<usize>,

    /// GraphQL protection: maximum selection depth.
    #[arg(long, env = "WAF_GRAPHQL_MAX_DEPTH")]
    graphql_max_depth: Option<usize>,

    /// GraphQL protection: maximum number of aliased fields.
    #[arg(long, env = "WAF_GRAPHQL_MAX_ALIASES")]
    graphql_max_aliases: Option<usize>,

    /// GraphQL protection: maximum number of directives used.
    #[arg(long, env = "WAF_GRAPHQL_MAX_DIRECTIVES")]
    graphql_max_directives: Option<usize>,

    /// GraphQL protection: maximum computed query cost (schema-agnostic approximation).
    #[arg(long, env = "WAF_GRAPHQL_MAX_COST")]
    graphql_max_cost: Option<usize>,

    /// GraphQL cost model: scalar leaf field cost.
    #[arg(long, env = "WAF_GRAPHQL_COST_SCALAR_COST")]
    graphql_cost_scalar_cost: Option<usize>,

    /// GraphQL cost model: object field cost (field with sub-selection).
    #[arg(long, env = "WAF_GRAPHQL_COST_OBJECT_COST")]
    graphql_cost_object_cost: Option<usize>,

    /// GraphQL cost model: multiplier applied per nesting level (e.g. 1.5).
    #[arg(long, env = "WAF_GRAPHQL_COST_DEPTH_FACTOR")]
    graphql_cost_depth_cost_factor: Option<f64>,

    /// GraphQL cost model: treat fragments as inline (disables depth multiplier propagation through fragments).
    #[arg(
        long,
        env = "WAF_GRAPHQL_COST_FLATTEN_FRAGMENTS",
        default_missing_value = "true",
        num_args = 0..=1
    )]
    graphql_cost_flatten_fragments: Option<bool>,

    /// GraphQL cost model: ignore introspection fields (__schema/__type) for cost calculation.
    #[arg(
        long,
        env = "WAF_GRAPHQL_COST_IGNORE_INTROSPECTION",
        default_missing_value = "true",
        num_args = 0..=1
    )]
    graphql_cost_ignore_introspection: Option<bool>,

    /// GraphQL cost model: added cost when a fragment spread recurses (cycle detection).
    #[arg(long, env = "WAF_GRAPHQL_COST_FRAGMENT_RECURSION_COST")]
    graphql_cost_fragment_recursion_cost: Option<usize>,

    /// GraphQL protection: max `variables` JSON bytes (approx; computed by re-serializing the variables value).
    #[arg(long, env = "WAF_GRAPHQL_MAX_VARIABLES_BYTES")]
    graphql_max_variables_bytes: Option<usize>,

    /// GraphQL protection: max nesting depth of the `variables` JSON value.
    #[arg(long, env = "WAF_GRAPHQL_MAX_VARIABLES_DEPTH")]
    graphql_max_variables_depth: Option<usize>,

    /// GraphQL protection: max total keys inside the `variables` JSON value.
    #[arg(long, env = "WAF_GRAPHQL_MAX_VARIABLES_KEYS")]
    graphql_max_variables_keys: Option<usize>,

    /// GraphQL protection: max length of any array inside the `variables` JSON value.
    #[arg(long, env = "WAF_GRAPHQL_MAX_VARIABLES_ARRAY_LEN")]
    graphql_max_variables_array_len: Option<usize>,

    /// GraphQL response protection: strip "Did you mean ..." field suggestions from JSON errors.
    #[arg(
        long,
        env = "WAF_GRAPHQL_BLOCK_FIELD_SUGGESTIONS",
        default_missing_value = "true",
        num_args = 0..=1
    )]
    graphql_block_field_suggestions: Option<bool>,

    /// GraphQL response protection: max response bytes to buffer for suggestion stripping.
    #[arg(long, env = "WAF_GRAPHQL_MAX_RESPONSE_BYTES")]
    graphql_max_response_bytes: Option<usize>,
}

#[derive(Clone)]
struct AppState {
    mode: WafMode,
    upstream: Url,
    client: Client<HttpsConnector<HttpConnector>>,
    modsec: Option<Arc<ModSecurity>>,
    wirefilter_expr: Option<Arc<String>>,
    max_body_bytes: usize,
    graphql_sec: GraphqlSecurityConfig,
}

fn build_scheme() -> Scheme {
    // Keep this scheme small and stable. If the expression references an unknown field,
    // parsing will fail at startup (good: fail fast).
    Scheme! {
        http.method: Bytes,
        http.host: Bytes,
        http.user_agent: Bytes,
        http.content_type: Bytes,
        http.request.uri.path: Bytes,
        http.request.uri.query: Bytes,
        http.request.headers.authorization: Bytes,
        http.request.headers.x_forwarded_for: Bytes,
        http.request.headers.x_real_ip: Bytes,
    }
}

fn opt_header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn evaluate_wirefilter(expr: &str, req: &Request<Body>) -> Result<bool> {
    // Per-request compilation (Filter isn't Send/Sync in this crate version).
    let scheme = build_scheme();
    let ast = scheme
        .parse(expr)
        .map_err(|e| anyhow!("wirefilter parse error: {e}"))?;
    let filter = ast.compile();

    let mut ctx = ExecutionContext::new(&scheme);

    let method = req.method().as_str();
    let host = opt_header_str(req.headers(), header::HOST).unwrap_or_default();
    let ua = opt_header_str(req.headers(), header::USER_AGENT).unwrap_or_default();
    let ct = opt_header_str(req.headers(), header::CONTENT_TYPE).unwrap_or_default();
    let path = req.uri().path();
    let query = req.uri().query().unwrap_or_default();
    let auth = opt_header_str(req.headers(), header::AUTHORIZATION).unwrap_or_default();
    let xff = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let xri = req
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    ctx.set_field_value("http.method", method)
        .map_err(|e| anyhow!("wirefilter set http.method failed: {e}"))?;
    ctx.set_field_value("http.host", host)
        .map_err(|e| anyhow!("wirefilter set http.host failed: {e}"))?;
    ctx.set_field_value("http.user_agent", ua)
        .map_err(|e| anyhow!("wirefilter set http.user_agent failed: {e}"))?;
    ctx.set_field_value("http.content_type", ct)
        .map_err(|e| anyhow!("wirefilter set http.content_type failed: {e}"))?;
    ctx.set_field_value("http.request.uri.path", path)
        .map_err(|e| anyhow!("wirefilter set http.request.uri.path failed: {e}"))?;
    ctx.set_field_value("http.request.uri.query", query)
        .map_err(|e| anyhow!("wirefilter set http.request.uri.query failed: {e}"))?;
    ctx.set_field_value("http.request.headers.authorization", auth)
        .map_err(|e| anyhow!("wirefilter set http.request.headers.authorization failed: {e}"))?;
    ctx.set_field_value("http.request.headers.x_forwarded_for", xff)
        .map_err(|e| anyhow!("wirefilter set http.request.headers.x_forwarded_for failed: {e}"))?;
    ctx.set_field_value("http.request.headers.x_real_ip", xri)
        .map_err(|e| anyhow!("wirefilter set http.request.headers.x_real_ip failed: {e}"))?;

    filter
        .execute(&ctx)
        .map_err(|e| anyhow!("wirefilter execution error: {e}"))
}

fn modsec_inspect(
    modsec: &ModSecurity,
    req: &Request<Body>,
    body: &HttpBodyBytes,
) -> zentinel_modsec::Result<Option<zentinel_modsec::Intervention>> {
    let mut tx = modsec.new_transaction();

    tx.process_uri(
        req.uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/"),
        req.method().as_str(),
        "HTTP/1.1",
    )?;

    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            let _ = tx.add_request_header(name.as_str(), v);
        }
    }

    tx.process_request_headers()?;
    if let Some(i) = tx.intervention() {
        return Ok(Some(i.clone()));
    }

    if !body.is_empty() {
        let _ = tx.append_request_body(body.as_ref());
        let _ = tx.process_request_body();
    }

    Ok(tx.intervention().cloned())
}

fn response_with_status(status: StatusCode, msg: &str) -> Response<Body> {
    let mut resp = Response::new(Body::from(msg.to_owned()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

fn wants_json(req: &Request<Body>) -> bool {
    let ct = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ct.contains("application/json") || ct.contains("+json") {
        return true;
    }
    let accept = req
        .headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    accept.contains("application/json") || accept.contains("+json")
}

fn blocked_response_for(req: &Request<Body>) -> Response<Body> {
    if wants_json(req) {
        let body = r#"{"error":"Bad Request (blocked by WAF)","blocked":true}"#;
        let mut resp = Response::new(Body::from(body));
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        resp
    } else {
        response_with_status(StatusCode::BAD_REQUEST, "Bad Request (blocked by WAF)\n")
    }
}

fn make_upstream_uri(upstream: &Url, req_uri: &Uri) -> Result<Uri> {
    let mut base = upstream.clone();
    base.set_path(req_uri.path());
    base.set_query(req_uri.query());
    base.as_str()
        .parse::<Uri>()
        .map_err(|e| anyhow!("invalid upstream uri: {e}"))
}

async fn handle_request(
    state: AppState,
    client_addr: SocketAddr,
    mut req: Request<Body>,
) -> Result<Response<Body>> {
    let started = Instant::now();

    // Fast path: in `off` mode, stream directly upstream (no buffering/inspection).
    if state.mode == WafMode::Off {
        let upstream_uri = make_upstream_uri(&state.upstream, req.uri())?;
        *req.uri_mut() = upstream_uri;

        if let Some(host) = state.upstream.host_str() {
            if let Ok(hv) = HeaderValue::from_str(host) {
                req.headers_mut().insert(header::HOST, hv);
            }
        }

        return state
            .client
            .request(req)
            .await
            .context("upstream request failed");
    }

    // Buffer request body once (needed for inspection and to forward).
    let body_bytes = to_bytes(req.body_mut())
        .await
        .context("read request body")?;
    if body_bytes.len() > state.max_body_bytes {
        warn!(
            client_ip = %client_addr.ip(),
            len = body_bytes.len(),
            max = state.max_body_bytes,
            "Request body too large for inspection"
        );
    }
    let inspected_body = if body_bytes.len() <= state.max_body_bytes {
        HttpBodyBytes::copy_from_slice(&body_bytes)
    } else {
        HttpBodyBytes::copy_from_slice(&body_bytes[..state.max_body_bytes])
    };
    let is_graphql = looks_like_graphql_request(&req, &inspected_body);

    // WAF decisions.
    let mut matched_wirefilter = false;
    let mut modsec_intervention: Option<zentinel_modsec::Intervention> = None;
    let mut matched_introspection = false;
    let mut graphql_reason: Option<&'static str> = None;

    if state.mode != WafMode::Off {
        let gm = evaluate_graphql_security(&state.graphql_sec, &req, &inspected_body)
            .unwrap_or_else(|_| graphql_security::GraphqlMatch::no_match());
        matched_introspection = gm.matched;
        graphql_reason = gm.reason;

        if matched_introspection && state.mode == WafMode::Audit {
            warn!(reason = %graphql_reason.unwrap_or("unknown"), "graphql_security_matched");
        }

        if let Some(expr) = &state.wirefilter_expr {
            matched_wirefilter = evaluate_wirefilter(expr, &req).unwrap_or(false);
        }

        if let Some(modsec) = &state.modsec {
            match modsec_inspect(modsec, &req, &inspected_body) {
                Ok(i) => modsec_intervention = i,
                Err(e) => {
                    warn!(error = %e, "modsec inspection error (failing open)");
                }
            }
        }
    }

    let should_block = state.mode == WafMode::Block
        && (matched_wirefilter || modsec_intervention.is_some() || matched_introspection);

    info!(
        client_ip = %client_addr.ip(),
        method = %req.method(),
        path = %req.uri(),
        matched_wirefilter,
        matched_introspection,
        graphql_reason = %graphql_reason.unwrap_or(""),
        modsec_intervention = %modsec_intervention.as_ref().map(|i| i.status).unwrap_or(0),
        mode = ?state.mode,
        should_block,
        elapsed_ms = started.elapsed().as_millis(),
        "request_inspected"
    );

    if should_block {
        // Per requirement: always return 400 on block.
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/400
        let mut resp = blocked_response_for(&req);
        resp.headers_mut()
            .insert("x-waf-blocked", HeaderValue::from_static("true"));
        return Ok(resp);
    }

    // Forward request upstream.
    let upstream_uri = make_upstream_uri(&state.upstream, req.uri())?;
    *req.uri_mut() = upstream_uri;

    // Ensure Host header points at upstream host.
    if let Some(host) = state.upstream.host_str() {
        if let Ok(hv) = HeaderValue::from_str(host) {
            req.headers_mut().insert(header::HOST, hv);
        }
    }

    // Replace consumed body.
    *req.body_mut() = Body::from(body_bytes);

    let resp = state
        .client
        .request(req)
        .await
        .context("upstream request failed")?;

    // Response-side GraphQL protection: strip field suggestions.
    if is_graphql && state.graphql_sec.block_field_suggestions {
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if ct.contains("application/json") || ct.contains("+json") {
            if let Some(len) = resp
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<usize>().ok())
            {
                if len > state.graphql_sec.max_response_bytes {
                    return Ok(resp);
                }
            }

            let (mut parts, body) = resp.into_parts();
            let body_bytes = to_bytes(body)
                .await
                .context("read upstream response body")?;
            if body_bytes.len() <= state.graphql_sec.max_response_bytes {
                if let Some(rewritten) = strip_graphql_field_suggestions(body_bytes.as_ref()) {
                    parts.headers.remove(header::CONTENT_LENGTH);
                    return Ok(Response::from_parts(parts, Body::from(rewritten)));
                }
            }
            return Ok(Response::from_parts(parts, Body::from(body_bytes)));
        }
    }

    Ok(resp)
}

fn load_modsec(paths: &[String]) -> Result<Option<Arc<ModSecurity>>> {
    if paths.is_empty() {
        return Ok(None);
    }

    let mut combined = String::new();
    for pattern in paths {
        let mut matched_any = false;
        for entry in glob(pattern).with_context(|| format!("invalid glob pattern: {pattern}"))? {
            let path = entry.with_context(|| format!("glob read failed: {pattern}"))?;
            matched_any = true;
            let txt = std::fs::read_to_string(&path)
                .with_context(|| format!("read modsec rules file: {}", path.display()))?;
            combined.push_str(&txt);
            combined.push('\n');
        }
        if !matched_any {
            // If the pattern didn't match as a glob, treat it as a literal path.
            let txt = std::fs::read_to_string(pattern)
                .with_context(|| format!("read modsec rules file: {pattern}"))?;
            combined.push_str(&txt);
            combined.push('\n');
        }
    }

    let ruleset = CompiledRuleset::from_string(&combined).context("compile modsec rules")?;
    Ok(Some(Arc::new(ModSecurity::new(ruleset))))
}

fn load_wirefilter_expr(expr: &Option<String>) -> Result<Option<Arc<String>>> {
    Ok(expr.as_ref().map(|s| Arc::new(s.clone())))
}

async fn run(cli: Cli) -> Result<()> {
    if !cli.disable_logging {
        // Logging: default to structured JSON, configurable via RUST_LOG.
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info,hyper=warn".into()),
            )
            .json()
            .init();
    }

    let file_cfg = if let Some(p) = &cli.config {
        Some(load_toml_config(p)?)
    } else {
        None
    };

    let listen_host = cli
        .listen_host
        .clone()
        .or_else(|| {
            file_cfg
                .as_ref()
                .and_then(|c| c.waf.as_ref()?.listen_host.clone())
        })
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let listen_port = cli
        .listen_port
        .or_else(|| file_cfg.as_ref().and_then(|c| c.waf.as_ref()?.listen_port))
        .unwrap_or(8080);
    let upstream_s = cli
        .upstream
        .clone()
        .or_else(|| {
            file_cfg
                .as_ref()
                .and_then(|c| c.waf.as_ref()?.upstream.clone())
        })
        .ok_or_else(|| anyhow!("missing upstream (set --upstream or waf.upstream in config)"))?;

    let mode = cli
        .mode
        .or_else(|| {
            file_cfg.as_ref().and_then(|c| {
                let m = c.waf.as_ref()?.mode.as_deref()?;
                match m.to_ascii_lowercase().as_str() {
                    "off" => Some(WafMode::Off),
                    "audit" => Some(WafMode::Audit),
                    "block" => Some(WafMode::Block),
                    _ => None,
                }
            })
        })
        .unwrap_or(WafMode::Block);

    let max_body_bytes = cli
        .max_body_bytes
        .or_else(|| {
            file_cfg
                .as_ref()
                .and_then(|c| c.waf.as_ref()?.max_body_bytes)
        })
        .unwrap_or(1024 * 1024);

    let wirefilter = cli.wirefilter.clone().or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.waf.as_ref()?.wirefilter.clone())
    });

    let modsec_rules = if !cli.modsec_rules.is_empty() {
        cli.modsec_rules.clone()
    } else {
        file_cfg
            .as_ref()
            .and_then(|c| c.waf.as_ref()?.modsec_rules.clone())
            .unwrap_or_default()
    };

    let upstream = Url::parse(&upstream_s).context("parse upstream URL")?;
    if upstream.scheme() != "http" && upstream.scheme() != "https" {
        return Err(anyhow!("upstream must be http:// or https://"));
    }

    let modsec = load_modsec(&modsec_rules)?;
    let wirefilter_expr = load_wirefilter_expr(&wirefilter)?;

    // Client tuning for higher req/s:
    // - enable TCP_NODELAY to reduce latency for small requests
    // - increase idle pool per host to reduce connect churn under load
    // - keep idle connections around longer
    let mut http = HttpConnector::new();
    http.set_nodelay(true);
    let https = HttpsConnector::new_with_connector(http);
    let client: Client<_> = Client::builder()
        .pool_max_idle_per_host(256)
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .build(https);

    let gql_enabled = cli
        .graphql_security
        .or_else(|| file_cfg.as_ref().and_then(|c| c.graphql.as_ref()?.enabled))
        .unwrap_or(true);
    let gql_block_introspection = cli
        .block_introspection
        .or_else(|| {
            file_cfg
                .as_ref()
                .and_then(|c| c.graphql.as_ref()?.block_introspection)
        })
        .unwrap_or(false);
    let gql_block_batch = cli
        .block_graphql_batch
        .or_else(|| {
            file_cfg
                .as_ref()
                .and_then(|c| c.graphql.as_ref()?.block_batch)
        })
        .unwrap_or(false);
    let gql_block_invalid = cli
        .graphql_block_invalid
        .or_else(|| {
            file_cfg
                .as_ref()
                .and_then(|c| c.graphql.as_ref()?.block_invalid_query)
        })
        .unwrap_or(true);
    let gql_allow_get = cli
        .graphql_allow_get
        .or_else(|| {
            file_cfg
                .as_ref()
                .and_then(|c| c.graphql.as_ref()?.allow_get)
        })
        .unwrap_or(false);
    let gql_allow_introspection_header =
        cli.graphql_allow_introspection_header.clone().or_else(|| {
            file_cfg
                .as_ref()
                .and_then(|c| c.graphql.as_ref()?.allow_introspection_header.clone())
        });
    let gql_max_query_bytes = cli.graphql_max_query_bytes.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.max_query_bytes)
    });
    let gql_max_depth = cli.graphql_max_depth.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.max_depth)
    });
    let gql_max_aliases = cli.graphql_max_aliases.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.max_aliases)
    });
    let gql_max_directives = cli.graphql_max_directives.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.max_directives)
    });
    let gql_max_cost = cli
        .graphql_max_cost
        .or_else(|| file_cfg.as_ref().and_then(|c| c.graphql.as_ref()?.max_cost));
    let gql_cost_scalar_cost = cli.graphql_cost_scalar_cost.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.cost_scalar_cost)
    });
    let gql_cost_object_cost = cli.graphql_cost_object_cost.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.cost_object_cost)
    });
    let gql_cost_depth_cost_factor = cli.graphql_cost_depth_cost_factor.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.cost_depth_cost_factor)
    });
    let gql_cost_flatten_fragments = cli.graphql_cost_flatten_fragments.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.cost_flatten_fragments)
    });
    let gql_cost_ignore_introspection = cli.graphql_cost_ignore_introspection.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.cost_ignore_introspection)
    });
    let gql_cost_fragment_recursion_cost = cli.graphql_cost_fragment_recursion_cost.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.cost_fragment_recursion_cost)
    });
    let gql_max_variables_bytes = cli.graphql_max_variables_bytes.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.max_variables_bytes)
    });
    let gql_max_variables_depth = cli.graphql_max_variables_depth.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.max_variables_depth)
    });
    let gql_max_variables_keys = cli.graphql_max_variables_keys.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.max_variables_keys)
    });
    let gql_max_variables_array_len = cli.graphql_max_variables_array_len.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.max_variables_array_len)
    });
    let gql_block_field_suggestions = cli.graphql_block_field_suggestions.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.block_field_suggestions)
    });
    let gql_max_response_bytes = cli.graphql_max_response_bytes.or_else(|| {
        file_cfg
            .as_ref()
            .and_then(|c| c.graphql.as_ref()?.max_response_bytes)
    });

    let state = AppState {
        mode,
        upstream,
        client,
        modsec,
        wirefilter_expr,
        max_body_bytes,
        graphql_sec: GraphqlSecurityConfig {
            enabled: gql_enabled,
            block_introspection: gql_block_introspection,
            allow_introspection_header: gql_allow_introspection_header,
            allow_get: gql_allow_get,
            max_query_bytes: gql_max_query_bytes,
            max_depth: gql_max_depth,
            max_aliases: gql_max_aliases,
            max_directives: gql_max_directives,
            max_cost: gql_max_cost,
            cost_scalar_cost: gql_cost_scalar_cost.unwrap_or(1),
            cost_object_cost: gql_cost_object_cost.unwrap_or(2),
            cost_depth_cost_factor: gql_cost_depth_cost_factor.unwrap_or(1.5),
            cost_flatten_fragments: gql_cost_flatten_fragments.unwrap_or(false),
            cost_ignore_introspection: gql_cost_ignore_introspection.unwrap_or(true),
            cost_fragment_recursion_cost: gql_cost_fragment_recursion_cost.unwrap_or(1000),
            max_variables_bytes: gql_max_variables_bytes,
            max_variables_depth: gql_max_variables_depth,
            max_variables_keys: gql_max_variables_keys,
            max_variables_array_len: gql_max_variables_array_len,
            block_batch: gql_block_batch,
            block_invalid_query: gql_block_invalid,
            block_field_suggestions: gql_block_field_suggestions.unwrap_or(true),
            max_response_bytes: gql_max_response_bytes.unwrap_or(256 * 1024),
        },
    };

    let addr: SocketAddr = format!("{listen_host}:{listen_port}")
        .parse()
        .context("parse listen address")?;

    let make_svc = make_service_fn(move |conn: &AddrStream| {
        let state = state.clone();
        let remote = conn.remote_addr();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let state = state.clone();
                async move {
                    match handle_request(state, remote, req).await {
                        Ok(resp) => Ok::<_, hyper::Error>(resp),
                        Err(e) => {
                            error!(error = %e, "request handling error");
                            Ok(response_with_status(
                                StatusCode::BAD_GATEWAY,
                                "Upstream error\n",
                            ))
                        }
                    }
                }
            }))
        }
    });

    info!(listen = %addr, "starting_waf");
    let server = Server::bind(&addr)
        .http1_keepalive(true)
        .http1_half_close(false)
        .serve(make_svc);

    let graceful = server.with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutdown_signal");
    });

    graceful.await?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load config early so we can size the Tokio runtime from it.
    let file_cfg = if let Some(p) = &cli.config {
        Some(load_toml_config(p)?)
    } else {
        None
    };

    let worker_threads = cli
        .worker_threads
        .or_else(|| {
            file_cfg
                .as_ref()
                .and_then(|c| c.waf.as_ref()?.worker_threads)
        })
        .unwrap_or(2);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    rt.block_on(async move { run(cli).await })
}
