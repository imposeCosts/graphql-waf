use zentinel_modsec::{CompiledRuleset, ModSecurity};

fn check(modsec: &ModSecurity, uri: &str, method: &str, body: &str, label: &str) {
    let mut tx = modsec.new_transaction();
    tx.process_uri(uri, method, "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    if !body.is_empty() {
        let _ = tx.append_request_body(body.as_bytes());
        let _ = tx.process_request_body();
    }
    match tx.intervention() {
        Some(i) => println!("{label}: BLOCKED (status {})", i.status),
        None => println!("{label}: passed"),
    }
}

fn main() {
    let combined = std::fs::read_to_string("/tmp/test_rule_isolated.conf").unwrap();
    let ruleset = CompiledRuleset::from_string(&combined).unwrap();
    let modsec = ModSecurity::new(ruleset);

    check(&modsec, "/graphql", "POST", r#"{"query":"query { __schema { queryType { name } } }"}"#, "introspection __schema");
    check(&modsec, "/graphql", "POST", r#"{"query":"query { __type(name: \"Foo\") { name } }"}"#, "introspection __type");
    check(&modsec, "/graphql", "POST", r#"{"query":"query { custom__typeThing }"}"#, "benign field ending in __type (expected false positive, this rule is blunt)");
    check(&modsec, "/graphql", "POST", r#"[{"query":"{ ping }"},{"query":"{ ping }"}]"#, "batched array body");
    check(&modsec, "/graphql", "POST", r#"{"query":"query { ping }"}"#, "normal query");
    check(&modsec, "/graphql?query=%7Bping%7D", "GET", "", "graphql over GET");
    check(&modsec, "/graphql", "GET", "", "plain GET no query");

    let aliases: String = (0..60).map(|i| format!("a{i}: ping(id: {i}) {{ ")).collect();
    let body = format!(r#"{{"query":"query {{ {aliases} }}"}}"#);
    check(&modsec, "/graphql", "POST", &body, "60 aliased fields");
}
