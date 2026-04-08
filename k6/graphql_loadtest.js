import http from "k6/http";
import { check, sleep } from "k6";

const BASE_URL = __ENV.K6_BASE_URL || "http://127.0.0.1:8080";
const GRAPHQL_URL = `${BASE_URL.replace(/\/$/, "")}/graphql`;

export const options = {
  vus: Number(__ENV.K6_VUS || 20),
  duration: __ENV.K6_DURATION || "20s",
  // For max req/s measurements, set K6_DISCARD_BODIES=true to reduce client overhead.
  discardResponseBodies: __ENV.K6_DISCARD_BODIES === "true",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500"],
  },
};

function gql(query, variables = {}, expectedStatus = 200, expectWafBlocked = false) {
  const payload = JSON.stringify({ query, variables });
  const res = http.post(GRAPHQL_URL, payload, {
    headers: {
      "content-type": "application/json",
    },
    timeout: __ENV.K6_TIMEOUT || "30s",
  });

  check(res, {
    [`status is ${expectedStatus}`]: (r) => r.status === expectedStatus,
    "has data or errors": (r) => {
      if (__ENV.K6_SKIP_JSON_CHECK === "true") return true;
      try {
        const j = r.json();
        return j && (j.data || j.errors);
      } catch (_) {
        return false;
      }
    },
    "waf blocked header when expected": (r) =>
      !expectWafBlocked || (r.headers["X-Waf-Blocked"] || r.headers["x-waf-blocked"]) === "true",
  });

  return res;
}

function gqlBatch(queries, expectedStatus = 200, expectWafBlocked = false) {
  const payload = JSON.stringify(queries.map((q) => ({ query: q })));
  const res = http.post(GRAPHQL_URL, payload, {
    headers: {
      "content-type": "application/json",
    },
    timeout: __ENV.K6_TIMEOUT || "30s",
  });

  check(res, {
    [`status is ${expectedStatus}`]: (r) => r.status === expectedStatus,
    "waf blocked header when expected": (r) =>
      !expectWafBlocked || (r.headers["X-Waf-Blocked"] || r.headers["x-waf-blocked"]) === "true",
  });

  return res;
}

const QUERY_PING = `query { ping }`;
const QUERY_NESTED = `query($depth: Int!) {
  nestedNode(depth: $depth) {
    id name depth
    child { id name depth child { id name depth } }
  }
}`;
const QUERY_BIGLIST = `query($size: Int!) { bigList(size: $size) { id name } }`;
const QUERY_FIB = `query($n: Int!) { fib(n: $n) }`;
const QUERY_INTROSPECTION = `query {
  __schema {
    queryType { name }
  }
}`;
const QUERY_DEPTH_HEAVY = `query { a { b { c { d } } } }`;
const QUERY_ALIASES_HEAVY = `query { a1: ping a2: ping }`;
const QUERY_DIRECTIVES_HEAVY = `query { ping @skip(if: true) @include(if: true) }`;
const QUERY_COST_HEAVY = `query {
  a { b { c { d { e { f { g { h { i { j } } } } } } } } }
}`;

export default function () {
  const mode = __ENV.K6_MODE || "mixed";

  if (mode === "ping") {
    gql(QUERY_PING);
  } else if (mode === "nested") {
    gql(QUERY_NESTED, { depth: Number(__ENV.K6_DEPTH || 60) });
  } else if (mode === "biglist") {
    gql(QUERY_BIGLIST, { size: Number(__ENV.K6_SIZE || 5000) });
  } else if (mode === "fib") {
    gql(QUERY_FIB, { n: Number(__ENV.K6_N || 42) });
  } else if (mode === "introspection") {
    // Expect the WAF to block this when --block-introspection is enabled in block mode.
    gql(QUERY_INTROSPECTION, {}, 400, true);
  } else if (mode === "batch") {
    // Expect the WAF to block batched operations when --block-graphql-batch is enabled in block mode.
    gqlBatch([QUERY_PING, QUERY_PING], 400, true);
  } else if (mode === "depth") {
    // Expect the WAF to block when --graphql-max-depth is set low enough.
    gql(QUERY_DEPTH_HEAVY, {}, 400, true);
  } else if (mode === "aliases") {
    // Expect the WAF to block when --graphql-max-aliases is set low enough.
    gql(QUERY_ALIASES_HEAVY, {}, 400, true);
  } else if (mode === "directives") {
    // Expect the WAF to block when --graphql-max-directives is set low enough.
    gql(QUERY_DIRECTIVES_HEAVY, {}, 400, true);
  } else if (mode === "max_query_bytes") {
    // Expect the WAF to block when --graphql-max-query-bytes is set low enough.
    // Make a long query string without relying on server schema.
    const pad = "x".repeat(Number(__ENV.K6_PAD || 200));
    gql(`query { ping } # ${pad}`, {}, 400, true);
  } else if (mode === "cost") {
    // Expect the WAF to block when --graphql-max-cost is set low enough.
    gql(QUERY_COST_HEAVY, {}, 400, true);
  } else {
    // Mixed workload
    const r = Math.random();
    if (r < 0.4) gql(QUERY_PING);
    else if (r < 0.6) gql(QUERY_NESTED, { depth: Number(__ENV.K6_DEPTH || 60) });
    else if (r < 0.85) gql(QUERY_BIGLIST, { size: Number(__ENV.K6_SIZE || 5000) });
    else gql(QUERY_FIB, { n: Number(__ENV.K6_N || 42) });
  }

  sleep(Number(__ENV.K6_SLEEP || 0));
}

