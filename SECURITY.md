# Security Policy

## Supported Versions

This project does not yet publish tagged releases with long-term support; security fixes are
applied to the `main` branch. Please run the latest `main` (or the latest GitHub Release, if one
exists) to receive fixes.

## Reporting a Vulnerability

Please **do not open a public GitHub issue** for security vulnerabilities.

Instead, report vulnerabilities privately to **christogoosen@gmail.com**. Include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce (a minimal request/config that triggers it is ideal).
- The commit/version affected.

You should expect an initial response within a few business days. Once a fix is available, it
will be released and the reporter credited (unless anonymity is requested).

## Scope Notes

- `dvga-like-server/` and the files under `rules/`, `gotestwaf-testcases/`, and `k6/` are
  intentionally vulnerable/permissive test fixtures used to exercise `graphql-waf` itself — do
  not report issues found only in that harness as vulnerabilities in the WAF.
- `rules/modsec-gotestwaf-100.conf` and similar files under `rules/` are explicitly tuned to
  score well against the GoTestWAF benchmark and are documented as **not** production defaults;
  see `CONTRIBUTING.md`.
