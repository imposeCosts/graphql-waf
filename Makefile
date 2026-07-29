.PHONY: help build run run-dev fmt clippy test clean semgrep-install semgrep k6-install wkhtmltopdf-install k6-report upstream-run waf-run perf-k6 perf-k6-introspection-block perf-k6-batch-block perf-k6-depth-block perf-k6-aliases-block perf-k6-directives-block perf-k6-max-query-bytes-block perf-k6-cost-block gotestwaf-pull gotestwaf-scan gotestwaf-scan-owasp gotestwaf-scan-owasp-api gotestwaf-scan-graphql run-dev-gotestwaf-graphql

WAF_URL ?= http://127.0.0.1:8080
UPSTREAM_URL ?= http://127.0.0.1:4000
K6_SCRIPT ?= k6/graphql_loadtest.js
K6_BASE_URL ?= $(WAF_URL)
K6_VUS ?= 20
K6_DURATION ?= 20s
K6_MODE ?= mixed
K6_SUMMARY_JSON ?= reports/k6-summary.json
K6_REPORT_HTML ?= reports/k6-report.html
K6_REPORT_PDF ?= reports/k6-report.pdf
WAF_ARGS ?= --listen-host 127.0.0.1 --listen-port 8080 --mode off
# Defaults for `make run-dev` (blocks using all GraphQL protections + limits).
RUN_DEV_WAF_ARGS ?= --listen-host 127.0.0.1 --listen-port 8080 --mode block --graphql-security --graphql-block-non-graphql-paths --block-introspection --block-graphql-batch --graphql-max-query-bytes 8192 --graphql-max-depth 20 --graphql-max-aliases 50 --graphql-max-directives 50 --graphql-max-cost 200
REPORT_DIR ?= reports
# Our WAF currently blocks with HTTP 400 and a distinctive body string.
GTW_BLOCK_STATUS ?= 400
# Match either plaintext block page or JSON error body.
# Note: avoid double quotes here because it is passed inside a double-quoted CLI argument.
GTW_BLOCK_REGEX ?= blocked by WAF|blocked\\s*:\\s*true
# GraphQL URL for GoTestWAF --graphqlURL (owasp-api graphql / graphql-post need a real endpoint).
# Default: same host as WAF with /graphql (typical DVGA / Apollo path through the proxy).
GTW_GRAPHQL_URL ?= $(WAF_URL)/graphql
# HTTP client: use gohttp to avoid Chrome/CDP JSON decode noise in logs (IPAddressSpace errors).
GTW_HTTP_CLIENT ?= gohttp
GTW_EXTRA ?=
# GoTestWAF selection. If GTW_TESTCASE is empty, the full test set runs.
GTW_TESTSET ?= owasp-api
GTW_TESTCASE ?=

help:
	@echo "Targets:"
	@echo "  make build              Build (debug)"
	@echo "  make run ARGS='...'     Run WAF (debug) with default UPSTREAM_URL"
	@echo "  make semgrep-install    Install semgrep (pipx preferred)"
	@echo "  make semgrep            Run semgrep scan"
	@echo "  make k6-install         Install k6 (Linux package managers)"
	@echo "  make wkhtmltopdf-install Install wkhtmltopdf (for PDF reports)"
	@echo "  make upstream-run       Run local GraphQL upstream on :4000"
	@echo "  make waf-run            Run WAF proxying to upstream"
	@echo "  make run-dev            Run upstream + WAF (dev loop)"
	@echo "  make perf-k6            Run upstream + WAF + k6 load test"
	@echo "  make k6-report          Run perf-k6 and export PDF report"
	@echo "  make perf-k6-introspection-block  Verify introspection is blocked"
	@echo "  make perf-k6-batch-block          Verify GraphQL batch is blocked"
	@echo "  make perf-k6-depth-block          Verify depth limit blocks"
	@echo "  make perf-k6-aliases-block        Verify alias limit blocks"
	@echo "  make perf-k6-directives-block     Verify directive limit blocks"
	@echo "  make perf-k6-max-query-bytes-block Verify max query bytes blocks"
	@echo "  make perf-k6-cost-block           Verify cost limit blocks"
	@echo "  make fmt                Format code"
	@echo "  make clippy             Run clippy (warns as errors)"
	@echo "  make clean              Clean target dir"
	@echo "  make gotestwaf-pull      Pull wallarm/gotestwaf image"
	@echo "  make gotestwaf-scan      Scan WAF_URL (default $(WAF_URL))"
	@echo "  make gotestwaf-scan-owasp     OWASP Top-10 test set"
	@echo "  make gotestwaf-scan-owasp-api  OWASP API test set"
	@echo "  make gotestwaf-scan-graphql   GraphQL test case (owasp-api/graphql)"
	@echo ""
	@echo "GoTestWAF vars:"
	@echo "  WAF_URL=http://127.0.0.1:8080"
	@echo "  UPSTREAM_URL=http://127.0.0.1:4000"
	@echo ""
	@echo "k6 vars:"
	@echo "  K6_SCRIPT=$(K6_SCRIPT)"
	@echo "  K6_BASE_URL=$(K6_BASE_URL)        (e.g. http://127.0.0.1:8080)"
	@echo "  K6_VUS=$(K6_VUS)"
	@echo "  K6_DURATION=$(K6_DURATION)"
	@echo "  K6_MODE=$(K6_MODE)                (ping|nested|biglist|fib|introspection|batch|depth|aliases|directives|max_query_bytes|cost|mixed)"
	@echo "  K6_SUMMARY_JSON=$(K6_SUMMARY_JSON)"
	@echo "  K6_REPORT_PDF=$(K6_REPORT_PDF)"
	@echo "  WAF_ARGS='$(WAF_ARGS)'            (extra args passed to WAF)"
	@echo "  RUN_DEV_WAF_ARGS='$(RUN_DEV_WAF_ARGS)' (default args used by run-dev)"
	@echo "  GTW_BLOCK_STATUS=400           (status code used when blocking)"
	@echo "  GTW_BLOCK_REGEX=$(GTW_BLOCK_REGEX) (regex to detect block page/body)"
	@echo "  GTW_GRAPHQL_URL=$(GTW_GRAPHQL_URL) (GoTestWAF --graphqlURL; set empty to skip GraphQL subtests)"
	@echo "  GTW_HTTP_CLIENT=$(GTW_HTTP_CLIENT) (--httpClient; use gohttp, not chrome)"
	@echo "  GTW_EXTRA=                     (extra gotestwaf flags)"

build:
	cargo build

run:
	cargo run -- --upstream "$(UPSTREAM_URL)" $(ARGS)

run-dev:
	@bash -lc '\
		set -euo pipefail; \
		echo "Building upstream + WAF..."; \
		cargo build --manifest-path dvga-like-server/Cargo.toml; \
		cargo build; \
		up_bin="dvga-like-server/target/debug/dvga-like-server"; \
		waf_bin="target/debug/graphql-waf"; \
		cores="$$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"; \
		waf_threads_arg=""; \
		if [[ "$(RUN_DEV_WAF_ARGS)" != *"--worker-threads"* ]]; then \
			waf_threads_arg="--worker-threads $$cores"; \
		fi; \
		echo "Starting upstream at $(UPSTREAM_URL)"; \
		"$$up_bin" >/tmp/dvga-like-server.log 2>&1 & up_pid="$$!"; \
		sleep 0.5; \
		echo "Starting WAF at $(WAF_URL) -> $(UPSTREAM_URL)"; \
		"$$waf_bin" --upstream "$(UPSTREAM_URL)" $$waf_threads_arg $(RUN_DEV_WAF_ARGS) >/tmp/graphql-waf.log 2>&1 & waf_pid="$$!"; \
		trap "kill $$waf_pid $$up_pid >/dev/null 2>&1 || true" EXIT INT TERM; \
		echo ""; \
		echo "Upstream: $(UPSTREAM_URL)/graphql (graphiql: $(UPSTREAM_URL)/graphiql)"; \
		echo "WAF:      $(WAF_URL)/graphql"; \
		echo "Logs:     /tmp/dvga-like-server.log /tmp/graphql-waf.log"; \
		echo ""; \
		echo "Press Ctrl+C to stop."; \
		wait \
	'

semgrep-install:
	@bash -lc '\
		set -euo pipefail; \
		if command -v semgrep >/dev/null 2>&1; then \
			semgrep --version; \
			exit 0; \
		fi; \
		if command -v pipx >/dev/null 2>&1; then \
			pipx install semgrep; \
			semgrep --version; \
			exit 0; \
		fi; \
		if command -v pip3 >/dev/null 2>&1; then \
			echo "pipx not found; installing semgrep with pip3 --user"; \
			pip3 install --user semgrep; \
			python3 -m semgrep --version; \
			exit 0; \
		fi; \
		echo "Need pipx or pip3 to install semgrep"; \
		exit 2; \
	'

semgrep:
	@bash -lc '\
		set -euo pipefail; \
		command -v semgrep >/dev/null 2>&1 || { echo "semgrep is required (run: make semgrep-install)"; exit 2; }; \
		semgrep --config .semgrep.yml --config p/rust --config p/security-audit --error --metrics=off; \
	'

k6-install:
	@bash -lc '\
		set -euo pipefail; \
		if command -v k6 >/dev/null 2>&1; then \
			echo "k6 already installed: $$(k6 version 2>/dev/null || true)"; \
			exit 0; \
		fi; \
		if command -v apt-get >/dev/null 2>&1; then \
			echo "Installing k6 via APT (dl.k6.io repo)..."; \
			sudo mkdir -p /etc/apt/keyrings; \
			curl -fsSL https://dl.k6.io/key.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/k6-archive-keyring.gpg; \
			echo "deb [signed-by=/etc/apt/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list >/dev/null; \
			sudo apt-get update; \
			sudo apt-get install -y k6; \
			k6 version; \
			exit 0; \
		fi; \
		if command -v dnf >/dev/null 2>&1; then \
			echo "Installing k6 via DNF (dl.k6.io repo)..."; \
			sudo dnf install -y dnf-plugins-core; \
			sudo dnf config-manager --add-repo https://dl.k6.io/rpm/k6.repo; \
			sudo dnf install -y k6; \
			k6 version; \
			exit 0; \
		fi; \
		if command -v yum >/dev/null 2>&1; then \
			echo "Installing k6 via YUM (dl.k6.io repo)..."; \
			sudo yum install -y yum-utils; \
			sudo yum-config-manager --add-repo https://dl.k6.io/rpm/k6.repo; \
			sudo yum install -y k6; \
			k6 version; \
			exit 0; \
		fi; \
		echo "Unsupported package manager. Install k6 manually: https://k6.io/docs/get-started/installation/"; \
		exit 2; \
	'

wkhtmltopdf-install:
	@bash -lc '\
		set -euo pipefail; \
		if command -v wkhtmltopdf >/dev/null 2>&1; then \
			echo "wkhtmltopdf already installed"; \
			exit 0; \
		fi; \
		if command -v apt-get >/dev/null 2>&1; then \
			echo "Installing wkhtmltopdf via APT..."; \
			sudo apt-get update; \
			sudo apt-get install -y wkhtmltopdf; \
			wkhtmltopdf --version; \
			exit 0; \
		fi; \
		echo "Unsupported package manager. Install wkhtmltopdf manually."; \
		exit 2; \
	'

upstream-run:
	cargo run --manifest-path dvga-like-server/Cargo.toml

waf-run:
	cargo run -- --upstream "$(UPSTREAM_URL)" $(ARGS)

perf-k6:
	@bash -lc '\
		set -euo pipefail; \
		command -v k6 >/dev/null 2>&1 || { echo "k6 is required (install: https://k6.io/)"; exit 2; }; \
		echo "Building upstream + WAF..."; \
		cargo build --manifest-path dvga-like-server/Cargo.toml; \
		cargo build; \
		up_bin="dvga-like-server/target/debug/dvga-like-server"; \
		waf_bin="target/debug/graphql-waf"; \
		cores="$$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"; \
		waf_threads_arg=""; \
		if [[ "$(WAF_ARGS)" != *"--worker-threads"* ]]; then \
			waf_threads_arg="--worker-threads $$cores"; \
		fi; \
		echo "Starting upstream at $(UPSTREAM_URL)"; \
		"$$up_bin" >/tmp/dvga-like-server.log 2>&1 & up_pid="$$!"; \
		sleep 0.5; \
		echo "Starting WAF at $(WAF_URL) -> $(UPSTREAM_URL)"; \
		"$$waf_bin" --upstream "$(UPSTREAM_URL)" $$waf_threads_arg $(WAF_ARGS) >/tmp/graphql-waf.log 2>&1 & waf_pid="$$!"; \
		trap "kill $$waf_pid $$up_pid >/dev/null 2>&1 || true" EXIT INT TERM; \
		sleep 0.5; \
		echo "Running k6 (script: $(K6_SCRIPT))"; \
		mkdir -p "$(REPORT_DIR)"; \
		K6_BASE_URL="$(K6_BASE_URL)" K6_VUS="$(K6_VUS)" K6_DURATION="$(K6_DURATION)" K6_MODE="$(K6_MODE)" \
			k6 run --summary-export "$(K6_SUMMARY_JSON)" "$(K6_SCRIPT)"; \
		echo "Done." \
	'

k6-report:
	@bash -lc '\
		set -euo pipefail; \
		$(MAKE) perf-k6; \
		command -v python3 >/dev/null 2>&1 || { echo "python3 is required to build the HTML report"; exit 2; }; \
		python3 scripts/k6_summary_to_html.py "$(K6_SUMMARY_JSON)" "$(K6_REPORT_HTML)"; \
		command -v wkhtmltopdf >/dev/null 2>&1 || { echo "wkhtmltopdf is required (run: make wkhtmltopdf-install)"; exit 2; }; \
		wkhtmltopdf --quiet "$(K6_REPORT_HTML)" "$(K6_REPORT_PDF)"; \
		echo "Wrote $(K6_REPORT_PDF)"; \
	'

perf-k6-introspection-block:
	@$(MAKE) perf-k6 K6_MODE=introspection K6_VUS=1 K6_DURATION=2s \
		WAF_ARGS='--listen-host 127.0.0.1 --listen-port 8080 --mode block --graphql-security --block-introspection'

perf-k6-batch-block:
	@$(MAKE) perf-k6 K6_MODE=batch K6_VUS=1 K6_DURATION=2s \
		WAF_ARGS='--listen-host 127.0.0.1 --listen-port 8080 --mode block --graphql-security --block-graphql-batch'

perf-k6-depth-block:
	@$(MAKE) perf-k6 K6_MODE=depth K6_VUS=1 K6_DURATION=2s \
		WAF_ARGS='--listen-host 127.0.0.1 --listen-port 8080 --mode block --graphql-security --graphql-max-depth 3'

perf-k6-aliases-block:
	@$(MAKE) perf-k6 K6_MODE=aliases K6_VUS=1 K6_DURATION=2s \
		WAF_ARGS='--listen-host 127.0.0.1 --listen-port 8080 --mode block --graphql-security --graphql-max-aliases 1'

perf-k6-directives-block:
	@$(MAKE) perf-k6 K6_MODE=directives K6_VUS=1 K6_DURATION=2s \
		WAF_ARGS='--listen-host 127.0.0.1 --listen-port 8080 --mode block --graphql-security --graphql-max-directives 1'

perf-k6-max-query-bytes-block:
	@$(MAKE) perf-k6 K6_MODE=max_query_bytes K6_VUS=1 K6_DURATION=2s K6_PAD=200 \
		WAF_ARGS='--listen-host 127.0.0.1 --listen-port 8080 --mode block --graphql-security --graphql-max-query-bytes 10'

perf-k6-cost-block:
	@$(MAKE) perf-k6 K6_MODE=cost K6_VUS=1 K6_DURATION=2s \
		WAF_ARGS='--listen-host 127.0.0.1 --listen-port 8080 --mode block --graphql-security --graphql-max-cost 5'

fmt:
	cargo fmt

clippy:
	cargo clippy -- -D warnings

test:
	cargo test --all-features
	cargo test --manifest-path dvga-like-server/Cargo.toml --all-features

clean:
	cargo clean

gotestwaf-pull:
	docker pull wallarm/gotestwaf

gotestwaf-scan:
	mkdir -p "$(REPORT_DIR)"
	docker run --rm --network="host" -v "$(PWD)/$(REPORT_DIR):/app/reports" \
		wallarm/gotestwaf --url="$(WAF_URL)" --noEmailReport --skipWAFIdentification \
		--skipWAFBlockCheck --httpClient="$(GTW_HTTP_CLIENT)" \
		--blockStatusCodes="$(GTW_BLOCK_STATUS)" $(if $(GTW_BLOCK_REGEX),--blockRegex="$(GTW_BLOCK_REGEX)",) \
		$(if $(GTW_GRAPHQL_URL),--graphqlURL="$(GTW_GRAPHQL_URL)",) $(GTW_EXTRA)

gotestwaf-scan-owasp:
	mkdir -p "$(REPORT_DIR)"
	docker run --rm --network="host" -v "$(PWD)/$(REPORT_DIR):/app/reports" \
		wallarm/gotestwaf --url="$(WAF_URL)" --noEmailReport --skipWAFIdentification \
		--skipWAFBlockCheck --httpClient="$(GTW_HTTP_CLIENT)" \
		--blockStatusCodes="$(GTW_BLOCK_STATUS)" $(if $(GTW_BLOCK_REGEX),--blockRegex="$(GTW_BLOCK_REGEX)",) \
		$(if $(GTW_GRAPHQL_URL),--graphqlURL="$(GTW_GRAPHQL_URL)",) \
		--testSet=owasp $(GTW_EXTRA)

gotestwaf-scan-owasp-api:
	mkdir -p "$(REPORT_DIR)"
	docker run --rm --network="host" -v "$(PWD)/$(REPORT_DIR):/app/reports" \
		wallarm/gotestwaf --url="$(WAF_URL)" --noEmailReport --skipWAFIdentification \
		--skipWAFBlockCheck --httpClient="$(GTW_HTTP_CLIENT)" \
		--blockStatusCodes="$(GTW_BLOCK_STATUS)" $(if $(GTW_BLOCK_REGEX),--blockRegex="$(GTW_BLOCK_REGEX)",) \
		$(if $(GTW_GRAPHQL_URL),--graphqlURL="$(GTW_GRAPHQL_URL)",) \
		--testSet=owasp-api $(GTW_EXTRA)

gotestwaf-scan-graphql:
	mkdir -p "$(REPORT_DIR)"
	docker run --rm --network="host" -v "$(PWD)/$(REPORT_DIR):/app/reports" \
		wallarm/gotestwaf --url="$(WAF_URL)" --noEmailReport --skipWAFIdentification \
		--addDebugHeader \
		--skipWAFBlockCheck --httpClient="$(GTW_HTTP_CLIENT)" \
		--blockStatusCodes="$(GTW_BLOCK_STATUS)" $(if $(GTW_BLOCK_REGEX),--blockRegex="$(GTW_BLOCK_REGEX)",) \
		--testSet=owasp-api --testCase=graphql \
		$(if $(GTW_GRAPHQL_URL),--graphqlURL="$(GTW_GRAPHQL_URL)",) $(GTW_EXTRA)

# One-shot: start upstream + WAF (RUN_DEV_WAF_ARGS) then run GoTestWAF.
# Defaults to the full OWASP API test set; optionally narrow with GTW_TESTCASE.
run-dev-gotestwaf-graphql:
	@bash -lc '\
		set -euo pipefail; \
		command -v docker >/dev/null 2>&1 || { echo "docker is required for GoTestWAF"; exit 2; }; \
		echo "Building upstream + WAF..."; \
		cargo build --manifest-path dvga-like-server/Cargo.toml; \
		cargo build; \
		up_bin="dvga-like-server/target/debug/dvga-like-server"; \
		waf_bin="target/debug/graphql-waf"; \
		cores="$$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"; \
		waf_threads_arg=""; \
		if [[ "$(RUN_DEV_WAF_ARGS)" != *"--worker-threads"* ]]; then \
			waf_threads_arg="--worker-threads $$cores"; \
		fi; \
		echo "Starting upstream at $(UPSTREAM_URL)"; \
		"$$up_bin" >/tmp/dvga-like-server.log 2>&1 & up_pid="$$!"; \
		sleep 0.5; \
		echo "Starting WAF at $(WAF_URL) -> $(UPSTREAM_URL)"; \
		"$$waf_bin" --upstream "$(UPSTREAM_URL)" $$waf_threads_arg $(RUN_DEV_WAF_ARGS) >/tmp/graphql-waf.log 2>&1 & waf_pid="$$!"; \
		trap "kill $$waf_pid $$up_pid >/dev/null 2>&1 || true" EXIT INT TERM; \
		echo "Waiting for WAF to serve GraphQL POST..."; \
		for i in $$(seq 1 40); do \
			code="$$(curl -sS -m 2 -o /dev/null -w "%{http_code}" \
				-H "content-type: application/json" \
				--data "{\"query\":\"query { ping }\"}" \
				"$(WAF_URL)/graphql" 2>/dev/null || true)"; \
			if [[ "$$code" == "200" ]]; then break; fi; \
			sleep 0.25; \
		done; \
		if [[ "$$code" != "200" ]]; then \
			echo "WAF GraphQL endpoint did not become ready (last HTTP $$code)"; \
			echo "Upstream log: /tmp/dvga-like-server.log"; \
			echo "WAF log:      /tmp/graphql-waf.log"; \
			exit 2; \
		fi; \
		echo "Running GoTestWAF against $(WAF_URL) (testSet=$(GTW_TESTSET) testCase=$(GTW_TESTCASE))"; \
		gtw_case_arg=""; \
		if [[ -n "$(GTW_TESTCASE)" ]]; then gtw_case_arg="--testCase=$(GTW_TESTCASE)"; fi; \
		$(MAKE) gotestwaf-scan GTW_EXTRA="--addDebugHeader --testSet=$(GTW_TESTSET) $$gtw_case_arg $(GTW_EXTRA)"; \
		echo "Done. Reports in $(REPORT_DIR)/"; \
		opener=""; \
		if command -v xdg-open >/dev/null 2>&1; then opener="xdg-open"; fi; \
		if command -v open >/dev/null 2>&1; then opener="open"; fi; \
		if [[ -n "$$opener" ]]; then \
			pdf="$$(ls -t "$(REPORT_DIR)"/*.pdf 2>/dev/null | head -n 1 || true)"; \
			html="$$(ls -t "$(REPORT_DIR)"/*.html 2>/dev/null | head -n 1 || true)"; \
			if [[ -n "$$pdf" ]]; then \
				echo "Opening report: $$pdf"; \
				"$$opener" "$$pdf" >/dev/null 2>&1 || true; \
			elif [[ -n "$$html" ]]; then \
				echo "Opening report: $$html"; \
				"$$opener" "$$html" >/dev/null 2>&1 || true; \
			else \
				echo "No PDF/HTML report found to open."; \
			fi; \
		else \
			echo "No browser opener found (xdg-open/open)."; \
		fi; \
	'
