use std::convert::Infallible;
use std::net::SocketAddr;

use graphql_waf::graphql_security::GraphqlSecurityConfig;
use graphql_waf::proxy::{handle_request, AppState, WafMode};
use http::{Request, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Response, Server};
use hyper_tls::HttpsConnector;
use url::Url;

fn base_graphql_sec() -> GraphqlSecurityConfig {
    GraphqlSecurityConfig {
        enabled: true,
        block_non_graphql_paths: false,
        block_introspection: true,
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
        block_field_suggestions: false,
        max_response_bytes: 256 * 1024,
    }
}

/// Spins up a tiny upstream server that echoes the request body back, and returns its address.
async fn spawn_echo_upstream() -> SocketAddr {
    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(|req: Request<Body>| async move {
            let body = hyper::body::to_bytes(req.into_body())
                .await
                .unwrap_or_default();
            Ok::<_, Infallible>(Response::new(Body::from(body)))
        }))
    });
    let server = Server::bind(&"127.0.0.1:0".parse().unwrap()).serve(make_svc);
    let addr = server.local_addr();
    tokio::spawn(server);
    addr
}

fn state_for(upstream_addr: SocketAddr, mode: WafMode, reject_oversized_body: bool) -> AppState {
    let https = HttpsConnector::new();
    let client: Client<_> = Client::builder().build(https);
    AppState {
        mode,
        upstream: Url::parse(&format!("http://{upstream_addr}")).unwrap(),
        client,
        modsec: None,
        wirefilter_expr: None,
        max_body_bytes: 64,
        reject_oversized_body,
        graphql_sec: base_graphql_sec(),
    }
}

fn client_addr() -> SocketAddr {
    "127.0.0.1:12345".parse().unwrap()
}

#[tokio::test]
async fn off_mode_forwards_without_inspection() {
    let upstream = spawn_echo_upstream().await;
    let state = state_for(upstream, WafMode::Off, true);

    let body = "x".repeat(1000); // far exceeds max_body_bytes, but Off mode never inspects
    let req = Request::builder()
        .method("POST")
        .uri("/graphql")
        .body(Body::from(body.clone()))
        .unwrap();

    let resp = handle_request(state, client_addr(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let echoed = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    assert_eq!(echoed.as_ref(), body.as_bytes());
}

#[tokio::test]
async fn block_mode_blocks_oversized_body_by_default() {
    let upstream = spawn_echo_upstream().await;
    let state = state_for(upstream, WafMode::Block, true);

    let oversized_body = "a".repeat(1000); // max_body_bytes is 64
    let req = Request::builder()
        .method("POST")
        .uri("/graphql")
        .body(Body::from(oversized_body))
        .unwrap();

    let resp = handle_request(state, client_addr(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.headers().get("x-waf-blocked").unwrap(),
        "true",
        "oversized body must be blocked in Block mode (P0-1 regression test)"
    );
}

#[tokio::test]
async fn block_mode_forwards_oversized_body_when_opted_out() {
    let upstream = spawn_echo_upstream().await;
    let state = state_for(upstream, WafMode::Block, false);

    let oversized_body = "a".repeat(1000);
    let req = Request::builder()
        .method("POST")
        .uri("/graphql")
        .body(Body::from(oversized_body.clone()))
        .unwrap();

    let resp = handle_request(state, client_addr(), req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "reject_oversized_body=false must restore the old permissive behavior"
    );
    let echoed = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    assert_eq!(echoed.as_ref(), oversized_body.as_bytes());
}

#[tokio::test]
async fn audit_mode_never_blocks_oversized_body() {
    let upstream = spawn_echo_upstream().await;
    let state = state_for(upstream, WafMode::Audit, true);

    let oversized_body = "a".repeat(1000);
    let req = Request::builder()
        .method("POST")
        .uri("/graphql")
        .body(Body::from(oversized_body))
        .unwrap();

    let resp = handle_request(state, client_addr(), req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "audit mode must never block, only warn"
    );
}

#[tokio::test]
async fn block_mode_blocks_introspection_query() {
    let upstream = spawn_echo_upstream().await;
    let state = state_for(upstream, WafMode::Block, true);

    let req = Request::builder()
        .method("POST")
        .uri("/graphql")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"query":"query { __schema { queryType { name } } }"}"#,
        ))
        .unwrap();

    let resp = handle_request(state, client_addr(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(resp.headers().get("x-waf-blocked").unwrap(), "true");
}

#[tokio::test]
async fn block_mode_allows_normal_query() {
    let upstream = spawn_echo_upstream().await;
    let state = state_for(upstream, WafMode::Block, true);

    let body = r#"{"query":"query { ping }"}"#;
    let req = Request::builder()
        .method("POST")
        .uri("/graphql")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = handle_request(state, client_addr(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
