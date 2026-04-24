use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TomlConfig {
    pub waf: Option<WafSection>,
    pub graphql: Option<GraphqlSection>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WafSection {
    pub listen_host: Option<String>,
    pub listen_port: Option<u16>,
    pub upstream: Option<String>,
    pub mode: Option<String>,
    pub modsec_rules: Option<Vec<String>>,
    pub wirefilter: Option<String>,
    pub max_body_bytes: Option<usize>,
    pub worker_threads: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct GraphqlSection {
    pub enabled: Option<bool>,
    pub block_non_graphql_paths: Option<bool>,
    pub block_introspection: Option<bool>,
    pub allow_introspection_header: Option<String>,
    pub allow_get: Option<bool>,
    pub block_invalid_query: Option<bool>,
    pub block_batch: Option<bool>,
    pub max_query_bytes: Option<usize>,
    pub max_depth: Option<usize>,
    pub max_aliases: Option<usize>,
    pub max_directives: Option<usize>,
    pub max_cost: Option<usize>,
    pub cost_scalar_cost: Option<usize>,
    pub cost_object_cost: Option<usize>,
    pub cost_depth_cost_factor: Option<f64>,
    pub cost_flatten_fragments: Option<bool>,
    pub cost_ignore_introspection: Option<bool>,
    pub cost_fragment_recursion_cost: Option<usize>,
    pub max_variables_bytes: Option<usize>,
    pub max_variables_depth: Option<usize>,
    pub max_variables_keys: Option<usize>,
    pub max_variables_array_len: Option<usize>,
    pub block_field_suggestions: Option<bool>,
    pub max_response_bytes: Option<usize>,
}

pub fn load_toml_config(path: &Path) -> Result<TomlConfig> {
    let txt = std::fs::read_to_string(path)
        .with_context(|| format!("read config file: {}", path.display()))?;
    let cfg = toml::from_str::<TomlConfig>(&txt)
        .with_context(|| format!("parse TOML config: {}", path.display()))?;
    Ok(cfg)
}
