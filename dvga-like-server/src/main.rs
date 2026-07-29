use std::{net::SocketAddr, time::Duration};

use async_graphql::{
    http::{playground_source, GraphQLPlaygroundConfig},
    Context, EmptyMutation, EmptySubscription, Object, Request as GqlRequest, Schema, SimpleObject,
};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::{Query, State},
    http::header,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use std::collections::HashMap;
use tower_http::trace::TraceLayer;
use tracing::{info, Level};

#[derive(Clone)]
struct AppState {
    schema: AppSchema,
}

type AppSchema = Schema<QueryRoot, EmptyMutation, EmptySubscription>;

#[derive(SimpleObject, Clone)]
struct Node {
    id: i32,
    name: String,
    depth: i32,
    child: Option<Box<Node>>,
}

struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Small, low-overhead query for baseline latency measurements.
    async fn ping(&self) -> &'static str {
        "pong"
    }

    /// Returns a recursively nested object to stress depth/recursion handling.
    async fn nested_node(&self, depth: i32) -> Node {
        build_node(0, depth.clamp(0, 200))
    }

    /// Returns a list to stress payload size / response serialization.
    async fn big_list(&self, size: i32) -> Vec<Node> {
        let size = size.clamp(0, 50_000) as usize;
        (0..size)
            .map(|i| Node {
                id: i as i32,
                name: format!("item-{i}"),
                depth: 0,
                child: None,
            })
            .collect()
    }

    /// CPU-ish work to stress request processing overhead.
    async fn fib(&self, n: i32) -> i64 {
        let n = n.clamp(0, 45) as u32;
        fib(n)
    }

    /// Sleep to simulate slow upstreams and exercise proxy timeouts.
    async fn sleep_ms(&self, ms: i32) -> i32 {
        let ms = ms.clamp(0, 10_000);
        tokio::time::sleep(Duration::from_millis(ms as u64)).await;
        ms
    }

    /// Returns some request metadata (useful to validate header forwarding).
    async fn request_meta(&self, ctx: &Context<'_>) -> RequestMeta {
        let headers = ctx
            .data_opt::<axum::http::HeaderMap>()
            .map(|hm| {
                hm.iter()
                    .filter_map(|(k, v)| {
                        v.to_str().ok().map(|vv| HeaderKV {
                            key: k.to_string(),
                            value: vv.to_string(),
                        })
                    })
                    .take(100)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        RequestMeta { headers }
    }
}

#[derive(SimpleObject)]
struct HeaderKV {
    key: String,
    value: String,
}

#[derive(SimpleObject)]
struct RequestMeta {
    headers: Vec<HeaderKV>,
}

fn build_node(cur: i32, max: i32) -> Node {
    if cur >= max {
        return Node {
            id: cur,
            name: format!("node-{cur}"),
            depth: cur,
            child: None,
        };
    }

    Node {
        id: cur,
        name: format!("node-{cur}"),
        depth: cur,
        child: Some(Box::new(build_node(cur + 1, max))),
    }
}

fn fib(n: u32) -> i64 {
    match n {
        0 => 0,
        1 => 1,
        _ => {
            let mut a: i64 = 0;
            let mut b: i64 = 1;
            for _ in 2..=n {
                let c = a + b;
                a = b;
                b = c;
            }
            b
        }
    }
}

async fn graphql_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    state
        .schema
        .execute(req.into_inner().data(headers))
        .await
        .into()
}

async fn graphql_get_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let query = params.get("query").cloned().unwrap_or_default();
    if query.trim().is_empty() {
        // Avoid noisy parser errors for GET /graphql without a query.
        let body = r#"{"errors":[{"message":"missing query parameter"}]}"#;
        return (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            body,
        )
            .into_response();
    }

    let req = GqlRequest::new(query).data(headers);
    GraphQLResponse::from(state.schema.execute(req).await).into_response()
}

async fn graphiql() -> impl IntoResponse {
    let html = playground_source(GraphQLPlaygroundConfig::new("/graphql"));
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(html),
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .compact()
        .init();

    let schema = Schema::build(QueryRoot, EmptyMutation, EmptySubscription).finish();
    let state = AppState { schema };

    let app = Router::new()
        .route("/graphql", post(graphql_handler).get(graphql_get_handler))
        .route("/graphiql", get(graphiql))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = "127.0.0.1:4000".parse()?;
    info!(listen = %addr, "dvga_like_server_listening");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These clamps exist so k6/gotestwaf load tests exercise bounded, predictable resource
    // usage. A silent regression here would let unbounded requests through and invalidate
    // load-test results without anyone noticing.

    fn test_schema() -> AppSchema {
        Schema::build(QueryRoot, EmptyMutation, EmptySubscription).finish()
    }

    /// Builds a GraphQL query nesting `child { ... }` `levels` times, terminating in `id`.
    /// Kept well under async-graphql-parser's own selection-set recursion limit (independent
    /// of this server's `depth.clamp(0, 200)`), which rejects deeply nested query *documents*
    /// long before 200 levels.
    fn nested_child_query(depth_arg: i32, levels: usize) -> String {
        let mut q = "id".to_string();
        for _ in 0..levels {
            q = format!("id child {{ {q} }}");
        }
        format!("{{ nestedNode(depth: {depth_arg}) {{ {q} }} }}")
    }

    #[test]
    fn fib_matches_known_values() {
        assert_eq!(fib(0), 0);
        assert_eq!(fib(1), 1);
        assert_eq!(fib(10), 55);
        assert_eq!(fib(45), 1_134_903_170);
    }

    #[test]
    fn build_node_chain_length_clamps_to_requested_max() {
        // `nested_node`'s resolver calls `build_node(0, depth.clamp(0, 200))`; verify the
        // underlying chain-building logic itself produces exactly `max + 1` nodes (ids 0..=max),
        // which is what the 200 clamp relies on to bound the response size.
        let root = build_node(0, 200);
        let mut count = 1;
        let mut cur = &root;
        while let Some(child) = &cur.child {
            count += 1;
            cur = child;
        }
        assert_eq!(count, 201);
    }

    #[tokio::test]
    async fn big_list_clamps_size_to_50_000() {
        let schema = test_schema();
        let res = schema
            .execute("{ bigList(size: 1000000) { id } }")
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let json = serde_json::to_value(res.data).unwrap();
        let list = json["bigList"].as_array().unwrap();
        assert_eq!(list.len(), 50_000);
    }

    #[tokio::test]
    async fn big_list_respects_smaller_requested_size() {
        let schema = test_schema();
        let res = schema.execute("{ bigList(size: 5) { id } }").await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let json = serde_json::to_value(res.data).unwrap();
        let list = json["bigList"].as_array().unwrap();
        assert_eq!(list.len(), 5);
    }

    #[tokio::test]
    async fn nested_node_does_not_truncate_below_a_modest_depth() {
        // Regression smoke test at the GraphQL wire level: requesting far more depth than the
        // 200 clamp allows must still honor at least this (much shallower) selection depth,
        // catching a gross regression (e.g. clamp accidentally set far below 200) without
        // fighting the parser's own much lower selection-set recursion limit.
        let levels = 20;
        let query = nested_child_query(100_000, levels);
        let res = schema_execute(&query).await;

        let json = serde_json::to_value(res.data).unwrap();
        let mut node = &json["nestedNode"];
        for expected_depth in 0..=levels {
            let id = node["id"].as_i64().unwrap();
            assert_eq!(id, expected_depth as i64);
            if expected_depth < levels {
                node = &node["child"];
                assert!(!node.is_null(), "expected non-null child at depth {expected_depth}");
            }
        }
    }

    async fn schema_execute(query: &str) -> async_graphql::Response {
        let schema = test_schema();
        let res = schema.execute(query).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        res
    }
}
