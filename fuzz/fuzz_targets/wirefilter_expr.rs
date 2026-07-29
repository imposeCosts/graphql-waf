#![no_main]

use graphql_waf::proxy::build_scheme;
use libfuzzer_sys::fuzz_target;

// Exercises wirefilter expression parsing (the `--wirefilter`/`WAF_WIREFILTER` config value,
// which can come from an operator-supplied config file) with arbitrary strings. This must only
// ever produce `Err`, never panic -- reinforces the fail-open error paths added in P0-2/P0-3.
fuzz_target!(|data: &[u8]| {
    if let Ok(expr) = std::str::from_utf8(data) {
        let scheme = build_scheme();
        if let Ok(ast) = scheme.parse(expr) {
            let _ = ast.compile();
        }
    }
});
