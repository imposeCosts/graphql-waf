use anyhow::Result;
use bytes::Bytes as HttpBodyBytes;
use graphql_parser::query::{Definition, Document, Selection, SelectionSet};
use http::{header, Request};
use hyper::Body;
use memchr::memmem;
use percent_encoding::percent_decode_str;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub struct GraphqlSecurityConfig {
    pub enabled: bool,
    pub block_introspection: bool,
    /// If set and present on the request, introspection blocking is bypassed.
    pub allow_introspection_header: Option<String>,
    pub max_query_bytes: Option<usize>,
    pub max_depth: Option<usize>,
    pub max_aliases: Option<usize>,
    pub max_directives: Option<usize>,
    pub max_cost: Option<usize>,
    pub block_batch: bool,
}

#[derive(Clone, Debug)]
pub struct GraphqlMatch {
    pub matched: bool,
    pub reason: Option<&'static str>,
}

impl GraphqlMatch {
    pub fn no_match() -> Self {
        Self {
            matched: false,
            reason: None,
        }
    }

    pub fn matched(reason: &'static str) -> Self {
        Self {
            matched: true,
            reason: Some(reason),
        }
    }
}

fn contains_introspection_bytes(haystack: &[u8]) -> bool {
    // Avoid false positives like "__typename" (which contains "__type" as a prefix).
    fn has_token(h: &[u8], token: &[u8]) -> bool {
        let mut start = 0usize;
        while let Some(pos) = memmem::find(&h[start..], token) {
            let at = start + pos;
            let next = h.get(at + token.len()).copied();
            let is_boundary = next.is_none()
                || matches!(next, Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r'))
                || matches!(
                    next,
                    Some(b'(')
                        | Some(b'{')
                        | Some(b'}')
                        | Some(b'[')
                        | Some(b']')
                        | Some(b':')
                        | Some(b',')
                        | Some(b')')
                );
            if is_boundary {
                return true;
            }
            start = at + token.len();
        }
        false
    }

    has_token(haystack, b"__schema") || has_token(haystack, b"__type")
}

fn extract_query_from_get(req: &Request<Body>) -> Option<String> {
    let raw = req.uri().query()?;

    // Standard GraphQL over GET: ?query=<document>
    for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
        if k == "query" {
            return Some(v.into_owned());
        }
    }

    // Some tools send the entire GraphQL request JSON in the query string (e.g. ?{"query":"..."}).
    // Best-effort: percent-decode the whole query string.
    let decoded = percent_decode_str(raw).decode_utf8_lossy().to_string();

    // If it looks like JSON, try to extract {"query": "..."}.
    if decoded.trim_start().starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&decoded) {
            if let Some(q) = v.get("query").and_then(|q| q.as_str()) {
                return Some(q.to_string());
            }
        }
    }

    // Fallback: treat the decoded string as the query document.
    Some(decoded)
}

fn content_type(req: &Request<Body>) -> &str {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

fn extract_query_from_body(req: &Request<Body>, inspected_body: &HttpBodyBytes) -> Option<String> {
    if inspected_body.is_empty() {
        return None;
    }

    // Fast path: application/graphql is the query document itself.
    let ct = content_type(req);
    if ct.starts_with("application/graphql") {
        return std::str::from_utf8(inspected_body.as_ref())
            .ok()
            .map(|s| s.to_string());
    }

    // JSON: {"query": "...", "variables": {...}}.
    if ct.starts_with("application/json") || ct.contains("+json") {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(inspected_body.as_ref()) {
            if v.is_array() {
                // Batched queries: [{query:...}, ...]
                return None;
            }
            return v
                .get("query")
                .and_then(|q| q.as_str())
                .map(|s| s.to_string());
        }
    }

    // Fallback: attempt to parse as utf-8 and treat it as a query-ish payload.
    std::str::from_utf8(inspected_body.as_ref())
        .ok()
        .map(|s| s.to_string())
}

fn is_batched_json(req: &Request<Body>, inspected_body: &HttpBodyBytes) -> bool {
    if inspected_body.is_empty() {
        return false;
    }
    let ct = content_type(req);
    if !(ct.starts_with("application/json") || ct.contains("+json")) {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(inspected_body.as_ref())
        .map(|v| v.is_array())
        .unwrap_or(false)
}

#[derive(Default)]
struct DocStats {
    aliases: usize,
    directives: usize,
}

fn max_depth_selection_set(set: &SelectionSet<String>) -> usize {
    fn sel_depth(sel: &Selection<String>) -> usize {
        match sel {
            Selection::Field(f) => {
                if f.selection_set.items.is_empty() {
                    1
                } else {
                    1 + max_depth_selection_set(&f.selection_set)
                }
            }
            Selection::FragmentSpread(_) => 1,
            Selection::InlineFragment(f) => {
                if f.selection_set.items.is_empty() {
                    1
                } else {
                    1 + max_depth_selection_set(&f.selection_set)
                }
            }
        }
    }

    set.items.iter().map(sel_depth).max().unwrap_or(0)
}

fn count_aliases_and_directives(doc: &Document<String>) -> DocStats {
    fn walk_set(set: &SelectionSet<String>, out: &mut DocStats) {
        for sel in &set.items {
            match sel {
                Selection::Field(f) => {
                    if f.alias.is_some() {
                        out.aliases += 1;
                    }
                    out.directives += f.directives.len();
                    walk_set(&f.selection_set, out);
                }
                Selection::InlineFragment(f) => {
                    out.directives += f.directives.len();
                    walk_set(&f.selection_set, out);
                }
                Selection::FragmentSpread(f) => {
                    out.directives += f.directives.len();
                }
            }
        }
    }

    let mut out = DocStats::default();
    for def in &doc.definitions {
        match def {
            Definition::Operation(op) => {
                // graphql-parser represents operations with an internal enum; selection_set is accessible via match.
                let set = match op {
                    graphql_parser::query::OperationDefinition::Query(q) => &q.selection_set,
                    graphql_parser::query::OperationDefinition::Mutation(m) => &m.selection_set,
                    graphql_parser::query::OperationDefinition::Subscription(s) => &s.selection_set,
                    graphql_parser::query::OperationDefinition::SelectionSet(s) => s,
                };
                walk_set(set, &mut out);
            }
            Definition::Fragment(f) => {
                out.directives += f.directives.len();
                walk_set(&f.selection_set, &mut out);
            }
        }
    }
    out
}

fn estimate_cost(doc: &Document<String>) -> usize {
    // First-pass cost model (schema-agnostic):
    // - Each field adds 1 cost
    // - Fragment spreads are expanded (cycle-safe)
    // - Inline fragments are traversed
    //
    // This is intentionally simple but effective at limiting huge selection trees.
    let mut fragments: HashMap<&str, &graphql_parser::query::FragmentDefinition<String>> =
        HashMap::new();
    for def in &doc.definitions {
        if let Definition::Fragment(f) = def {
            fragments.insert(f.name.as_str(), f);
        }
    }

    fn walk_set(
        set: &SelectionSet<String>,
        fragments: &HashMap<&str, &graphql_parser::query::FragmentDefinition<String>>,
        visiting: &mut HashSet<String>,
    ) -> usize {
        let mut cost = 0usize;
        for sel in &set.items {
            match sel {
                Selection::Field(f) => {
                    cost += 1;
                    cost += walk_set(&f.selection_set, fragments, visiting);
                }
                Selection::InlineFragment(f) => {
                    cost += walk_set(&f.selection_set, fragments, visiting);
                }
                Selection::FragmentSpread(sp) => {
                    let name = sp.fragment_name.as_str();
                    if visiting.insert(name.to_string()) {
                        if let Some(frag) = fragments.get(name) {
                            cost += walk_set(&frag.selection_set, fragments, visiting);
                        }
                        visiting.remove(name);
                    }
                }
            }
        }
        cost
    }

    let mut total = 0usize;
    for def in &doc.definitions {
        if let Definition::Operation(op) = def {
            let set = match op {
                graphql_parser::query::OperationDefinition::Query(q) => &q.selection_set,
                graphql_parser::query::OperationDefinition::Mutation(m) => &m.selection_set,
                graphql_parser::query::OperationDefinition::Subscription(s) => &s.selection_set,
                graphql_parser::query::OperationDefinition::SelectionSet(s) => s,
            };
            total += walk_set(set, &fragments, &mut HashSet::new());
        }
    }
    total
}

pub fn evaluate_graphql_security(
    cfg: &GraphqlSecurityConfig,
    req: &Request<Body>,
    inspected_body: &HttpBodyBytes,
) -> Result<GraphqlMatch> {
    if !cfg.enabled {
        return Ok(GraphqlMatch::no_match());
    }

    if cfg.block_batch && is_batched_json(req, inspected_body) {
        return Ok(GraphqlMatch::matched("graphql_batch_blocked"));
    }

    // Introspection: check in GET query, raw body bytes, and JSON "query".
    let allow_introspection = cfg
        .allow_introspection_header
        .as_deref()
        .and_then(|h| header::HeaderName::from_bytes(h.as_bytes()).ok())
        .is_some_and(|h| req.headers().contains_key(h));

    if cfg.block_introspection && !allow_introspection {
        // Fast path: if the raw query string contains introspection tokens, block.
        if let Some(qs) = req.uri().query() {
            if contains_introspection_bytes(qs.as_bytes()) {
                return Ok(GraphqlMatch::matched("graphql_introspection_blocked"));
            }
        }

        if let Some(q) = extract_query_from_get(req) {
            if contains_introspection_bytes(q.as_bytes()) {
                return Ok(GraphqlMatch::matched("graphql_introspection_blocked"));
            }
        }
        if contains_introspection_bytes(inspected_body.as_ref()) {
            return Ok(GraphqlMatch::matched("graphql_introspection_blocked"));
        }
    }

    let query =
        extract_query_from_get(req).or_else(|| extract_query_from_body(req, inspected_body));
    let Some(query) = query else {
        return Ok(GraphqlMatch::no_match());
    };

    if let Some(max_bytes) = cfg.max_query_bytes {
        if query.len() > max_bytes {
            return Ok(GraphqlMatch::matched("graphql_query_too_large"));
        }
    }

    // Parse and compute stats for depth/aliases/directives.
    let doc = match graphql_parser::parse_query::<String>(&query) {
        Ok(d) => d,
        Err(_) => {
            // Non-GraphQL payload (or invalid query) shouldn't be blocked by these heuristics.
            return Ok(GraphqlMatch::no_match());
        }
    };

    if let Some(max_depth) = cfg.max_depth {
        let mut depth = 0usize;
        for def in &doc.definitions {
            if let Definition::Operation(op) = def {
                let set = match op {
                    graphql_parser::query::OperationDefinition::Query(q) => &q.selection_set,
                    graphql_parser::query::OperationDefinition::Mutation(m) => &m.selection_set,
                    graphql_parser::query::OperationDefinition::Subscription(s) => &s.selection_set,
                    graphql_parser::query::OperationDefinition::SelectionSet(s) => s,
                };
                depth = depth.max(max_depth_selection_set(set));
            }
        }
        if depth > max_depth {
            return Ok(GraphqlMatch::matched("graphql_depth_exceeded"));
        }
    }

    let stats = count_aliases_and_directives(&doc);

    if let Some(max_aliases) = cfg.max_aliases {
        if stats.aliases > max_aliases {
            return Ok(GraphqlMatch::matched("graphql_aliases_exceeded"));
        }
    }

    if let Some(max_directives) = cfg.max_directives {
        if stats.directives > max_directives {
            return Ok(GraphqlMatch::matched("graphql_directives_exceeded"));
        }
    }

    if let Some(max_cost) = cfg.max_cost {
        let cost = estimate_cost(&doc);
        if cost > max_cost {
            return Ok(GraphqlMatch::matched("graphql_cost_exceeded"));
        }
    }

    Ok(GraphqlMatch::no_match())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    fn cfg_base() -> GraphqlSecurityConfig {
        GraphqlSecurityConfig {
            enabled: true,
            block_introspection: false,
            allow_introspection_header: None,
            max_query_bytes: None,
            max_depth: None,
            max_aliases: None,
            max_directives: None,
            max_cost: None,
            block_batch: false,
        }
    }

    fn req(method: Method, uri: &str, content_type: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(ct) = content_type {
            b = b.header(header::CONTENT_TYPE, ct);
        }
        b.body(Body::empty()).unwrap()
    }

    fn bytes(s: &str) -> HttpBodyBytes {
        HttpBodyBytes::from(s.to_owned())
    }

    #[test]
    fn disabled_does_not_match() {
        let cfg = GraphqlSecurityConfig {
            enabled: false,
            block_introspection: true,
            ..cfg_base()
        };
        let r = req(
            Method::GET,
            "/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D",
            None,
        );
        let m = evaluate_graphql_security(&cfg, &r, &HttpBodyBytes::new()).unwrap();
        assert!(!m.matched);
        assert!(m.reason.is_none());
    }

    #[test]
    fn blocks_introspection_from_get_query_param() {
        let cfg = GraphqlSecurityConfig {
            block_introspection: true,
            ..cfg_base()
        };
        let r = req(
            Method::GET,
            "/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D",
            None,
        );
        let m = evaluate_graphql_security(&cfg, &r, &HttpBodyBytes::new()).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_introspection_blocked"));
    }

    #[test]
    fn blocks_introspection_from_json_body_query_field() {
        let cfg = GraphqlSecurityConfig {
            block_introspection: true,
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/json"));
        let body = bytes(r#"{"query":"query { __schema { queryType { name } } }"}"#);
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_introspection_blocked"));
    }

    #[test]
    fn blocks_introspection_from_application_graphql_body() {
        let cfg = GraphqlSecurityConfig {
            block_introspection: true,
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/graphql"));
        let body = bytes("query { __type(name: \"Query\") { name } }");
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_introspection_blocked"));
    }

    #[test]
    fn blocks_batched_json_when_enabled() {
        let cfg = GraphqlSecurityConfig {
            block_batch: true,
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/json"));
        let body = bytes(r#"[{"query":"query { ping }"},{"query":"query { ping }"}]"#);
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_batch_blocked"));
    }

    #[test]
    fn enforces_max_query_bytes() {
        let cfg = GraphqlSecurityConfig {
            max_query_bytes: Some(10),
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/graphql"));
        let body = bytes("query { ping }");
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_query_too_large"));
    }

    #[test]
    fn enforces_max_depth() {
        let cfg = GraphqlSecurityConfig {
            max_depth: Some(3),
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/graphql"));
        let body = bytes("query { a { b { c { d } } } }");
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_depth_exceeded"));
    }

    #[test]
    fn enforces_max_aliases() {
        let cfg = GraphqlSecurityConfig {
            max_aliases: Some(1),
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/graphql"));
        let body = bytes("query { a1: ping a2: ping }");
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_aliases_exceeded"));
    }

    #[test]
    fn enforces_max_directives() {
        let cfg = GraphqlSecurityConfig {
            max_directives: Some(1),
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/graphql"));
        let body = bytes("query { ping @skip(if: true) @include(if: true) }");
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_directives_exceeded"));
    }

    #[test]
    fn invalid_query_does_not_match_limits() {
        let cfg = GraphqlSecurityConfig {
            max_depth: Some(1),
            max_aliases: Some(0),
            max_directives: Some(0),
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/graphql"));
        let body = bytes("not actually graphql");
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(!m.matched);
    }

    #[test]
    fn enforces_max_cost_with_fragments() {
        let cfg = GraphqlSecurityConfig {
            max_cost: Some(3),
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/graphql"));
        // cost = 1 (a) + 1 (b) + 1 (c) + 1 (d) = 4 > 3
        let body = bytes(
            r#"
            query {
              a { ...Frag }
            }
            fragment Frag on Query {
              b { c { d } }
            }
        "#,
        );
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_cost_exceeded"));
    }

    #[test]
    fn allows_introspection_when_allow_header_present() {
        let cfg = GraphqlSecurityConfig {
            block_introspection: true,
            allow_introspection_header: Some("x-gotestwaf-test".to_string()),
            ..cfg_base()
        };
        let mut r = req(Method::POST, "/graphql", Some("application/json"));
        r.headers_mut()
            .insert("x-gotestwaf-test", header::HeaderValue::from_static("1"));
        let body = bytes(r#"{"query":"query { __schema { queryType { name } } }"}"#);
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(!m.matched);
    }

    #[test]
    fn does_not_block_typename_meta_field() {
        let cfg = GraphqlSecurityConfig {
            block_introspection: true,
            ..cfg_base()
        };
        let r = req(Method::GET, "/graphql?query=%7B__typename%7D", None);
        let m = evaluate_graphql_security(&cfg, &r, &HttpBodyBytes::new()).unwrap();
        assert!(!m.matched);
    }

    #[test]
    fn blocks_introspection_when_querystring_is_json_blob() {
        let cfg = GraphqlSecurityConfig {
            block_introspection: true,
            ..cfg_base()
        };
        // GoTestWAF can send URL-encoded JSON in the query string (without query=).
        let r = req(
            Method::GET,
            "/graphql?%7B%22query%22:%22query%20%7B__schema%7BqueryType%7Bname%7D%7D%7D%22%7D",
            None,
        );
        let m = evaluate_graphql_security(&cfg, &r, &HttpBodyBytes::new()).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_introspection_blocked"));
    }
}
