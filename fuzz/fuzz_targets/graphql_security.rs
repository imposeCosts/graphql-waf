#![no_main]

use bytes::Bytes;
use graphql_waf::graphql_security::{
    evaluate_graphql_security, strip_graphql_field_suggestions, GraphqlSecurityConfig,
};
use http::Request;
use hyper::Body;
use libfuzzer_sys::fuzz_target;

fn cfg() -> GraphqlSecurityConfig {
    GraphqlSecurityConfig {
        enabled: true,
        block_non_graphql_paths: false,
        block_introspection: true,
        allow_introspection_header: None,
        allow_get: false,
        max_query_bytes: Some(8192),
        max_depth: Some(20),
        max_aliases: Some(50),
        max_directives: Some(50),
        max_cost: Some(200),
        cost_scalar_cost: 1,
        cost_object_cost: 2,
        cost_depth_cost_factor: 1.5,
        cost_flatten_fragments: false,
        cost_ignore_introspection: true,
        cost_fragment_recursion_cost: 1000,
        max_variables_bytes: Some(4096),
        max_variables_depth: Some(10),
        max_variables_keys: Some(100),
        max_variables_array_len: Some(1000),
        block_batch: true,
        block_invalid_query: true,
        block_field_suggestions: true,
        max_response_bytes: 256 * 1024,
    }
}

// Exercises the request-inspection path (query/variables extraction, introspection detection,
// depth/alias/directive/cost limits) and the response-side field-suggestion stripper with
// arbitrary bytes as the request/response body. This is the code fuzz-tested here specifically
// because P0-5 found a boundary bug in the introspection byte-scanner, and this whole path
// parses untrusted client input.
fuzz_target!(|data: &[u8]| {
    let cfg = cfg();
    let body = Bytes::copy_from_slice(data);

    let req = Request::builder()
        .method("POST")
        .uri("/graphql")
        .header("content-type", "application/json")
        .body(Body::empty())
        .unwrap();
    let _ = evaluate_graphql_security(&cfg, &req, &body);

    let get_req = Request::builder()
        .method("GET")
        .uri("/graphql")
        .body(Body::empty())
        .unwrap();
    let _ = evaluate_graphql_security(&cfg, &get_req, &body);

    let _ = strip_graphql_field_suggestions(data);
});
