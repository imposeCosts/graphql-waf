use anyhow::{Context, Result};
use clap::Parser;

use graphql_waf::config::load_toml_config;
use graphql_waf::proxy::resolve_worker_threads;
use graphql_waf::proxy::{run, Cli};

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load config early so we can size the Tokio runtime from it.
    let file_cfg = if let Some(p) = &cli.config {
        Some(load_toml_config(p)?)
    } else {
        None
    };

    let worker_threads = resolve_worker_threads(cli.worker_threads, file_cfg.as_ref())?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    rt.block_on(async move { run(cli).await })
}
