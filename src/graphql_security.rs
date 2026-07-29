use anyhow::Result;
use bytes::Bytes as HttpBodyBytes;
use graphql_parser::query::{Definition, Document, OperationDefinition, Selection, SelectionSet};
use http::{header, Request};
use hyper::Body;
use memchr::memmem;
use percent_encoding::percent_decode_str;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub struct GraphqlSecurityConfig {
    pub enabled: bool,
    /// If true, block requests that are not targeting GraphQL endpoints.
    ///
    /// This is useful when the proxy is intended to expose only GraphQL, and you
    /// want to reject REST/other endpoints early.
    pub block_non_graphql_paths: bool,
    pub block_introspection: bool,
    /// If set and present on the request, introspection blocking is bypassed.
    pub allow_introspection_header: Option<String>,
    /// Allow GraphQL-over-GET requests (default should typically be false).
    pub allow_get: bool,
    pub max_query_bytes: Option<usize>,
    pub max_depth: Option<usize>,
    pub max_aliases: Option<usize>,
    pub max_directives: Option<usize>,
    pub max_cost: Option<usize>,
    // Cost model tuning (roughly aligned with graphql-armor cost-limit defaults)
    pub cost_scalar_cost: usize,
    pub cost_object_cost: usize,
    pub cost_depth_cost_factor: f64,
    pub cost_flatten_fragments: bool,
    pub cost_ignore_introspection: bool,
    pub cost_fragment_recursion_cost: usize,
    /// Maximum size of the `variables` JSON value, in bytes (approx; computed by JSON re-serialization).
    pub max_variables_bytes: Option<usize>,
    /// Maximum nesting depth of the `variables` JSON value.
    pub max_variables_depth: Option<usize>,
    /// Maximum number of object keys in the `variables` JSON value (total across all objects).
    pub max_variables_keys: Option<usize>,
    /// Maximum length of any array inside the `variables` JSON value.
    pub max_variables_array_len: Option<usize>,
    pub block_batch: bool,
    /// If true, block requests that look like GraphQL but fail GraphQL parsing.
    pub block_invalid_query: bool,
    /// If true, strip "Did you mean ..." suggestions from GraphQL error messages in JSON responses.
    pub block_field_suggestions: bool,
    /// Maximum response body bytes to buffer for suggestion stripping.
    pub max_response_bytes: usize,
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
    // Avoid false positives like "__typename" (which contains "__type" as a prefix), and
    // like a custom field/identifier that merely *ends* with "__type"/"__schema"
    // (e.g. "custom__type(" or "foo__schema:") -- both the byte before and the byte after
    // the matched token must be a non-identifier boundary (or start/end of buffer) for it
    // to count as the real `__schema`/`__type` introspection field.
    fn is_ident_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    fn has_token(h: &[u8], token: &[u8]) -> bool {
        let mut start = 0usize;
        while let Some(pos) = memmem::find(&h[start..], token) {
            let at = start + pos;
            let prev = if at == 0 {
                None
            } else {
                h.get(at - 1).copied()
            };
            let is_prev_boundary = prev.is_none_or(|b| !is_ident_byte(b));

            let next = h.get(at + token.len()).copied();
            let is_next_boundary = next.is_none()
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
            if is_prev_boundary && is_next_boundary {
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

fn extract_variables_from_get(req: &Request<Body>) -> Option<serde_json::Value> {
    let raw = req.uri().query()?;

    // Standard GraphQL over GET: ?variables=<json>
    for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
        if k == "variables" {
            if v.trim().is_empty() {
                return None;
            }
            // variables can be urlencoded JSON
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&v) {
                return Some(val);
            }
            // Some clients double-encode; best-effort decode.
            let decoded = percent_decode_str(&v).decode_utf8_lossy().to_string();
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&decoded) {
                return Some(val);
            }
            return None;
        }
    }

    None
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

pub fn looks_like_graphql_request(req: &Request<Body>, inspected_body: &HttpBodyBytes) -> bool {
    // Heuristic: if we can extract a "query" from GET or body, treat as GraphQL.
    extract_query_from_get(req)
        .or_else(|| extract_query_from_body(req, inspected_body))
        .is_some()
}

/// True when the document is only the `__typename` meta-field (no args, no sub-selections).
///
/// GoTestWAF (and similar tooling) uses `GET ?query={__typename}` to detect a live GraphQL
/// endpoint. We still disable arbitrary GraphQL-over-GET by default (`allow_get: false`), but
/// allow this minimal probe so availability checks succeed through the WAF.
fn selection_set_is_only_typename_field(set: &SelectionSet<String>) -> bool {
    if set.items.len() != 1 {
        return false;
    }
    match &set.items[0] {
        Selection::Field(f) => {
            f.name == "__typename"
                && f.alias.is_none()
                && f.arguments.is_empty()
                && f.directives.is_empty()
                && f.selection_set.items.is_empty()
        }
        _ => false,
    }
}

fn is_typename_health_probe(query: &str) -> bool {
    let Ok(doc) = graphql_parser::parse_query::<String>(query) else {
        return false;
    };
    if doc.definitions.len() != 1 {
        return false;
    }
    match &doc.definitions[0] {
        Definition::Operation(op) => match op {
            OperationDefinition::SelectionSet(set) => selection_set_is_only_typename_field(set),
            OperationDefinition::Query(q) => {
                q.variable_definitions.is_empty()
                    && q.directives.is_empty()
                    && selection_set_is_only_typename_field(&q.selection_set)
            }
            OperationDefinition::Mutation(m) => {
                m.variable_definitions.is_empty()
                    && m.directives.is_empty()
                    && selection_set_is_only_typename_field(&m.selection_set)
            }
            OperationDefinition::Subscription(s) => {
                s.variable_definitions.is_empty()
                    && s.directives.is_empty()
                    && selection_set_is_only_typename_field(&s.selection_set)
            }
        },
        Definition::Fragment(_) => false,
    }
}

pub fn strip_graphql_field_suggestions(json_body: &[u8]) -> Option<Vec<u8>> {
    // Cheap pre-check before paying for a full JSON parse: the overwhelming majority of
    // responses are successful (no "errors" key at all), and a full `serde_json::from_slice`
    // into an owned `Value` tree is expensive for large bodies (e.g. list-shaped responses with
    // thousands of items). Skip straight past those without parsing anything.
    memmem::find(json_body, b"\"errors\"")?;

    // GraphQL errors are typically shaped like:
    // { "errors": [ { "message": "... Did you mean ...?" , ... } ], "data": ... }
    let mut v: serde_json::Value = serde_json::from_slice(json_body).ok()?;
    let errors = v.get_mut("errors")?.as_array_mut()?;

    let mut changed = false;
    for err in errors {
        let Some(msg) = err.get_mut("message") else {
            continue;
        };
        let Some(s) = msg.as_str() else { continue };

        // Remove trailing suggestion clause. Common patterns:
        // - " ... Did you mean \"foo\"?"
        // - " ... Did you mean the field \"foo\"?"
        // - " ... Did you mean ... ?"
        let cut = s.find(" Did you mean").or_else(|| s.find("did you mean"));
        if let Some(idx) = cut {
            let trimmed = s[..idx].trim_end().to_string();
            *msg = serde_json::Value::String(trimmed);
            changed = true;
        }
    }

    if !changed {
        return None;
    }
    serde_json::to_vec(&v).ok()
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

fn max_depth_selection_set(
    set: &SelectionSet<String>,
    fragments: &HashMap<&str, &graphql_parser::query::FragmentDefinition<String>>,
    visiting: &mut HashSet<String>,
) -> usize {
    fn sel_depth(
        sel: &Selection<String>,
        fragments: &HashMap<&str, &graphql_parser::query::FragmentDefinition<String>>,
        visiting: &mut HashSet<String>,
    ) -> usize {
        match sel {
            Selection::Field(f) => {
                if f.selection_set.items.is_empty() {
                    1
                } else {
                    1 + max_depth_selection_set(&f.selection_set, fragments, visiting)
                }
            }
            Selection::InlineFragment(f) => {
                if f.selection_set.items.is_empty() {
                    1
                } else {
                    1 + max_depth_selection_set(&f.selection_set, fragments, visiting)
                }
            }
            Selection::FragmentSpread(sp) => {
                // Expand fragment spreads to compute depth as-if flattened.
                // Cycle-safe: if we re-visit a fragment currently in the stack, stop expanding.
                let name = sp.fragment_name.as_str();
                if !visiting.insert(name.to_string()) {
                    return 1;
                }

                let depth = fragments
                    .get(name)
                    .map(|frag| max_depth_selection_set(&frag.selection_set, fragments, visiting))
                    .unwrap_or(0);

                visiting.remove(name);
                // Count the spread itself as 1 depth + fragment selection depth (if any).
                if depth == 0 {
                    1
                } else {
                    1 + depth
                }
            }
        }
    }

    set.items
        .iter()
        .map(|s| sel_depth(s, fragments, visiting))
        .max()
        .unwrap_or(0)
}

fn max_depth_document(doc: &Document<String>) -> usize {
    let mut fragments: HashMap<&str, &graphql_parser::query::FragmentDefinition<String>> =
        HashMap::new();
    for def in &doc.definitions {
        if let Definition::Fragment(f) = def {
            fragments.insert(f.name.as_str(), f);
        }
    }

    let mut depth = 0usize;
    for def in &doc.definitions {
        if let Definition::Operation(op) = def {
            let set = match op {
                graphql_parser::query::OperationDefinition::Query(q) => &q.selection_set,
                graphql_parser::query::OperationDefinition::Mutation(m) => &m.selection_set,
                graphql_parser::query::OperationDefinition::Subscription(s) => &s.selection_set,
                graphql_parser::query::OperationDefinition::SelectionSet(s) => s,
            };
            depth = depth.max(max_depth_selection_set(
                set,
                &fragments,
                &mut HashSet::new(),
            ));
        }
    }
    depth
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

fn compute_cost(doc: &Document<String>, cfg: &GraphqlSecurityConfig) -> f64 {
    // Configurable, schema-agnostic complexity model inspired by graphql-armor's cost-limit plugin:
    // - Scalars cost `scalar_cost`
    // - Objects (fields with sub-selection) cost `object_cost`
    // - Each nesting level multiplies child cost by `depth_cost_factor` (unless flatten_fragments=true)
    // - Fragment spreads are expanded (cycle-safe). Re-visits add `fragment_recursion_cost`.

    let mut fragments: HashMap<&str, &graphql_parser::query::FragmentDefinition<String>> =
        HashMap::new();
    for def in &doc.definitions {
        if let Definition::Fragment(f) = def {
            fragments.insert(f.name.as_str(), f);
        }
    }

    fn is_introspection_field(name: &str) -> bool {
        name == "__schema" || name == "__type"
    }

    fn walk_selection_set(
        set: &SelectionSet<String>,
        cfg: &GraphqlSecurityConfig,
        fragments: &HashMap<&str, &graphql_parser::query::FragmentDefinition<String>>,
        visiting: &mut HashSet<String>,
        depth: usize,
    ) -> f64 {
        let mut total = 0.0f64;
        for sel in &set.items {
            total += walk_selection(sel, cfg, fragments, visiting, depth);
        }
        total
    }

    fn walk_selection(
        sel: &Selection<String>,
        cfg: &GraphqlSecurityConfig,
        fragments: &HashMap<&str, &graphql_parser::query::FragmentDefinition<String>>,
        visiting: &mut HashSet<String>,
        depth: usize,
    ) -> f64 {
        match sel {
            Selection::Field(f) => {
                if cfg.cost_ignore_introspection && is_introspection_field(f.name.as_str()) {
                    return 0.0;
                }

                let has_children = !f.selection_set.items.is_empty();
                let mut cost = if has_children {
                    cfg.cost_object_cost as f64
                } else {
                    cfg.cost_scalar_cost as f64
                };

                if has_children {
                    for child in &f.selection_set.items {
                        let child_cost = walk_selection(child, cfg, fragments, visiting, depth + 1);
                        if cfg.cost_flatten_fragments {
                            cost += child_cost;
                        } else {
                            cost += cfg.cost_depth_cost_factor * child_cost;
                        }
                    }
                }
                cost
            }
            Selection::InlineFragment(f) => {
                // Inline fragments do not add base cost in this model; only their contents.
                walk_selection_set(&f.selection_set, cfg, fragments, visiting, depth)
            }
            Selection::FragmentSpread(sp) => {
                let name = sp.fragment_name.as_str();
                if !visiting.insert(name.to_string()) {
                    return cfg.cost_fragment_recursion_cost as f64;
                }
                let cost = fragments
                    .get(name)
                    .map(|frag| {
                        walk_selection_set(&frag.selection_set, cfg, fragments, visiting, depth)
                    })
                    .unwrap_or(0.0);
                visiting.remove(name);
                cost
            }
        }
    }

    let mut total = 0.0f64;
    for def in &doc.definitions {
        if let Definition::Operation(op) = def {
            let set = match op {
                graphql_parser::query::OperationDefinition::Query(q) => &q.selection_set,
                graphql_parser::query::OperationDefinition::Mutation(m) => &m.selection_set,
                graphql_parser::query::OperationDefinition::Subscription(s) => &s.selection_set,
                graphql_parser::query::OperationDefinition::SelectionSet(s) => s,
            };
            total += walk_selection_set(set, cfg, &fragments, &mut HashSet::new(), 0);
        }
    }
    total
}

fn extract_variables_from_body(
    req: &Request<Body>,
    inspected_body: &HttpBodyBytes,
) -> Option<serde_json::Value> {
    if inspected_body.is_empty() {
        return None;
    }
    let ct = content_type(req);
    if !(ct.starts_with("application/json") || ct.contains("+json")) {
        return None;
    }
    let v = serde_json::from_slice::<serde_json::Value>(inspected_body.as_ref()).ok()?;
    if v.is_array() {
        // batched handled elsewhere
        return None;
    }
    v.get("variables").cloned()
}

#[derive(Default)]
struct VariablesStats {
    depth: usize,
    keys: usize,
    max_array_len: usize,
    approx_bytes: usize,
}

fn variables_stats(v: &serde_json::Value) -> VariablesStats {
    fn walk(v: &serde_json::Value, depth: usize, out: &mut VariablesStats) {
        out.depth = out.depth.max(depth);
        match v {
            serde_json::Value::Object(map) => {
                out.keys += map.len();
                for (_, vv) in map {
                    walk(vv, depth + 1, out);
                }
            }
            serde_json::Value::Array(arr) => {
                out.max_array_len = out.max_array_len.max(arr.len());
                for vv in arr {
                    walk(vv, depth + 1, out);
                }
            }
            _ => {}
        }
    }

    let mut out = VariablesStats::default();
    walk(v, 1, &mut out);
    // Approximate bytes by serializing just the variables value.
    out.approx_bytes = serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0);
    out
}

pub fn evaluate_graphql_security(
    cfg: &GraphqlSecurityConfig,
    req: &Request<Body>,
    inspected_body: &HttpBodyBytes,
) -> Result<GraphqlMatch> {
    if !cfg.enabled {
        return Ok(GraphqlMatch::no_match());
    }

    // Introspection: check before the GraphQL-over-GET gate so GET introspection is reported as
    // `graphql_introspection_blocked` (not masked by `graphql_get_disabled`).
    let allow_introspection = cfg
        .allow_introspection_header
        .as_deref()
        .and_then(|h| header::HeaderName::from_bytes(h.as_bytes()).ok())
        .is_some_and(|h| req.headers().contains_key(h));

    if cfg.block_introspection && !allow_introspection {
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

    // If this looks like a GraphQL GET request, optionally block it.
    if req.method() == http::Method::GET && !cfg.allow_get {
        // Only block GET when it plausibly carries a GraphQL operation.
        // (Avoid breaking random GET traffic that just happens to pass through the proxy.)
        if let Some(q) = extract_query_from_get(req) {
            if !is_typename_health_probe(&q) {
                return Ok(GraphqlMatch::matched("graphql_get_disabled"));
            }
        }
    }

    // Variables limits: inspect variables from GET (?variables=) or JSON body {"variables": ...}
    // Apply before parsing the query document so a huge variables blob can't bypass cheap checks.
    let variables = extract_variables_from_get(req)
        .or_else(|| extract_variables_from_body(req, inspected_body));
    if let Some(vars) = variables {
        let st = variables_stats(&vars);

        if let Some(max_b) = cfg.max_variables_bytes {
            if st.approx_bytes > max_b {
                return Ok(GraphqlMatch::matched("graphql_variables_too_large"));
            }
        }
        if let Some(max_d) = cfg.max_variables_depth {
            if st.depth > max_d {
                return Ok(GraphqlMatch::matched("graphql_variables_depth_exceeded"));
            }
        }
        if let Some(max_k) = cfg.max_variables_keys {
            if st.keys > max_k {
                return Ok(GraphqlMatch::matched("graphql_variables_keys_exceeded"));
            }
        }
        if let Some(max_a) = cfg.max_variables_array_len {
            if st.max_array_len > max_a {
                return Ok(GraphqlMatch::matched("graphql_variables_array_exceeded"));
            }
        }
    }

    if cfg.block_batch && is_batched_json(req, inspected_body) {
        return Ok(GraphqlMatch::matched("graphql_batch_blocked"));
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
            if cfg.block_invalid_query {
                return Ok(GraphqlMatch::matched("graphql_invalid_query"));
            }
            return Ok(GraphqlMatch::no_match());
        }
    };

    if let Some(max_depth) = cfg.max_depth {
        let depth = max_depth_document(&doc);
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
        let cost = compute_cost(&doc, cfg);
        if cost > max_cost as f64 {
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
            block_non_graphql_paths: false,
            block_introspection: false,
            allow_introspection_header: None,
            allow_get: false,
            max_query_bytes: None,
            max_depth: None,
            max_aliases: None,
            max_directives: None,
            max_cost: None,
            cost_scalar_cost: 1,
            cost_object_cost: 2,
            cost_depth_cost_factor: 1.5,
            cost_flatten_fragments: false,
            cost_ignore_introspection: true,
            cost_fragment_recursion_cost: 1000,
            max_variables_bytes: None,
            max_variables_depth: None,
            max_variables_keys: None,
            max_variables_array_len: None,
            block_batch: false,
            block_invalid_query: false,
            block_field_suggestions: true,
            max_response_bytes: 256 * 1024,
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
    fn enforces_max_depth_with_fragments_flattened() {
        let cfg = GraphqlSecurityConfig {
            max_depth: Some(3),
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/graphql"));
        // Without fragment expansion, this used to undercount depth.
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
        // With default cost model (scalar=1, object=2, depth_factor=1.5), this is well above 3.
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
    fn cost_limit_can_ignore_introspection_fields() {
        let cfg = GraphqlSecurityConfig {
            max_cost: Some(1),
            block_introspection: false,
            cost_ignore_introspection: true,
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/graphql"));
        let body = bytes("query { __schema { types { name } } }");
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(!m.matched);
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

    #[test]
    fn blocks_graphql_get_when_disabled() {
        let cfg = GraphqlSecurityConfig {
            allow_get: false,
            ..cfg_base()
        };
        let r = req(Method::GET, "/graphql?query=%7Bping%7D", None);
        let m = evaluate_graphql_security(&cfg, &r, &HttpBodyBytes::new()).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_get_disabled"));
    }

    #[test]
    fn allows_gtw_typename_get_probe_when_get_disabled() {
        let cfg = GraphqlSecurityConfig {
            allow_get: false,
            ..cfg_base()
        };
        // GoTestWAF GraphQL availability check: GET with ?query={__typename}
        let r = req(Method::GET, "/graphql?query=%7B__typename%7D", None);
        let m = evaluate_graphql_security(&cfg, &r, &HttpBodyBytes::new()).unwrap();
        assert!(!m.matched);
    }

    #[test]
    fn allows_graphql_get_when_enabled() {
        let cfg = GraphqlSecurityConfig {
            allow_get: true,
            ..cfg_base()
        };
        let r = req(Method::GET, "/graphql?query=%7Bping%7D", None);
        let m = evaluate_graphql_security(&cfg, &r, &HttpBodyBytes::new()).unwrap();
        assert!(!m.matched);
    }

    #[test]
    fn strips_field_suggestions_from_graphql_errors() {
        let body = br#"{"errors":[{"message":"Cannot query field \"foo\" on type \"Query\". Did you mean \"bar\"?"}],"data":null}"#;
        let out = strip_graphql_field_suggestions(body).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let msg = v["errors"][0]["message"].as_str().unwrap();
        assert_eq!(msg, "Cannot query field \"foo\" on type \"Query\".");
    }

    #[test]
    fn returns_none_for_success_response_with_no_errors_key() {
        // A success-shaped body with no "errors" key anywhere (e.g. a bigList-style response
        // with thousands of items) has nothing to strip. This is also the case the cheap
        // `memmem` pre-check is meant to short-circuit before paying for a full JSON parse --
        // see the perf investigation in the accompanying plan for the measured before/after.
        let body = br#"{"data":{"bigList":[{"id":1,"name":"item-1"},{"id":2,"name":"item-2"}]}}"#;
        assert_eq!(strip_graphql_field_suggestions(body), None);
    }

    #[test]
    fn returns_none_for_malformed_body_without_errors_substring() {
        // Malformed JSON that doesn't even contain the "errors" substring must not panic or
        // attempt a parse -- the pre-check should reject it immediately, same as a well-formed
        // body would if it lacked an "errors" key.
        let body = b"not json at all, and definitely no e-r-r-o-r-s substring here";
        assert_eq!(strip_graphql_field_suggestions(body), None);
    }

    #[test]
    fn blocks_invalid_graphql_when_enabled() {
        let cfg = GraphqlSecurityConfig {
            block_invalid_query: true,
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/graphql"));
        let body = bytes("not actually graphql");
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_invalid_query"));
    }

    #[test]
    fn enforces_max_variables_bytes() {
        let cfg = GraphqlSecurityConfig {
            max_variables_bytes: Some(10),
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/json"));
        let body = bytes(r#"{"query":"query { ping }","variables":{"a":"0123456789"}} "#);
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_variables_too_large"));
    }

    #[test]
    fn enforces_max_variables_depth() {
        let cfg = GraphqlSecurityConfig {
            max_variables_depth: Some(3),
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/json"));
        let body = bytes(r#"{"query":"query { ping }","variables":{"a":{"b":{"c":{"d":1}}}}}"#);
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_variables_depth_exceeded"));
    }

    #[test]
    fn enforces_max_variables_keys() {
        let cfg = GraphqlSecurityConfig {
            max_variables_keys: Some(2),
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/json"));
        let body = bytes(r#"{"query":"query { ping }","variables":{"a":1,"b":2,"c":3}}"#);
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_variables_keys_exceeded"));
    }

    #[test]
    fn enforces_max_variables_array_len() {
        let cfg = GraphqlSecurityConfig {
            max_variables_array_len: Some(2),
            ..cfg_base()
        };
        let r = req(Method::POST, "/graphql", Some("application/json"));
        let body = bytes(r#"{"query":"query { ping }","variables":{"a":[1,2,3]}}"#);
        let m = evaluate_graphql_security(&cfg, &r, &body).unwrap();
        assert!(m.matched);
        assert_eq!(m.reason, Some("graphql_variables_array_exceeded"));
    }

    #[test]
    fn introspection_token_boundary_ignores_trailing_identifier_suffix() {
        // A field/identifier that merely *ends* with "__type"/"__schema" (e.g. a custom
        // field name) must not be flagged -- only the real `__type`/`__schema` fields.
        assert!(!contains_introspection_bytes(b"{ custom__type(id: 1) }"));
        assert!(!contains_introspection_bytes(b"{ foo__schema: bar }"));
        assert!(!contains_introspection_bytes(b"my__typeSomething"));
    }

    #[test]
    fn introspection_token_boundary_still_matches_real_fields() {
        assert!(contains_introspection_bytes(b"{__schema{queryType{name}}}"));
        assert!(contains_introspection_bytes(
            b"query { __type(name: \"Query\") { name } }"
        ));
        assert!(contains_introspection_bytes(b" __type "));
    }

    #[test]
    fn introspection_token_boundary_still_excludes_typename() {
        assert!(!contains_introspection_bytes(b"{ __typename }"));
    }
}
