import http from "k6/http";
import { check, sleep } from "k6";

const BASE_URL = __ENV.K6_BASE_URL || "http://127.0.0.1:8080";
const GRAPHQL_URL = `${BASE_URL.replace(/\/$/, "")}/graphql`;

export const options = {
  vus: Number(__ENV.K6_VUS || 50),
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
      // When discardResponseBodies is on (K6_DISCARD_BODIES=true, used by perf-k6-large to cut
      // client overhead at high VU counts), k6 gives back r.body === null for every response, so
      // r.json() has nothing to parse and this check would always fail regardless of what the
      // server actually returned. Skip it in that case -- the status check still verifies the
      // response succeeded.
      if (__ENV.K6_SKIP_JSON_CHECK === "true" || r.body === null) return true;
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
// Fragment reuse via aliases: the same fragment is expanded once per alias, multiplying the
// effective selection cost without the query text itself containing repeated field bodies --
// a naive depth/alias counter that only inspects the *unexpanded* document text could under-
// count this relative to an equivalent fully-inlined query. Regression test for the cost
// analyzer's fragment expansion (src/graphql_security.rs, cost_flatten_fragments).
const QUERY_FRAGMENT_AMPLIFICATION = `query {
  a1: nestedNode(depth: 5) { ...NodeFields }
  a2: nestedNode(depth: 5) { ...NodeFields }
  a3: nestedNode(depth: 5) { ...NodeFields }
  a4: nestedNode(depth: 5) { ...NodeFields }
  a5: nestedNode(depth: 5) { ...NodeFields }
  a6: nestedNode(depth: 5) { ...NodeFields }
  a7: nestedNode(depth: 5) { ...NodeFields }
  a8: nestedNode(depth: 5) { ...NodeFields }
}
fragment NodeFields on Node {
  id name depth
  child { id name depth child { id name depth child { id name depth } } }
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
  } else if (mode === "fragment_amplification") {
    // Expect the WAF to block when --graphql-max-cost (or --graphql-max-aliases) is set low
    // enough, same as "cost"/"aliases" -- this specifically exercises fragment-reuse-via-alias
    // amplification rather than repeated inline field bodies.
    gql(QUERY_FRAGMENT_AMPLIFICATION, {}, 400, true);
  } else if (mode === "ratelimit") {
    // PLACEHOLDER / future-proofing: graphql-waf has no rate-limiting feature yet (see
    // TODO.MD). This mode fires requests back-to-back from a single VU with no sleep between
    // them and currently expects every one to succeed -- once distributed rate limiting lands,
    // update the expected status/check here to assert some requests get throttled (e.g. 429).
    // This mode does not implement rate limiting itself; it only documents/tracks the gap.
    gql(QUERY_PING, {}, 200, false);
  } else if (mode === "auth_bypass") {
    // PLACEHOLDER: graphql-waf has no auth-aware rules today (confirmed empirically --
    // gotestwaf-testcases/owasp-api/api2-broken-auth.yml is 0% blocked by design, since
    // validating Authorization/JWT semantics is an application concern, not a WAF one). This
    // mode documents that a malformed bearer token currently reaches the upstream unmodified;
    // if auth-aware wirefilter/modsec rules are ever added, update the expected status here.
    const res = http.post(
      GRAPHQL_URL,
      JSON.stringify({ query: QUERY_PING }),
      {
        headers: {
          "content-type": "application/json",
          authorization: "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
        },
        timeout: __ENV.K6_TIMEOUT || "30s",
      }
    );
    check(res, { "status is 200 (no auth enforcement today)": (r) => r.status === 200 });
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

