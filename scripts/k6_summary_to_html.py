#!/usr/bin/env python3
import html
import json
import sys
from datetime import UTC, datetime


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: k6_summary_to_html.py <k6-summary.json> <out.html>", file=sys.stderr)
        return 2

    in_path, out_path = sys.argv[1], sys.argv[2]
    with open(in_path, "r", encoding="utf-8") as f:
        summary = json.load(f)

    metrics = summary.get("metrics", {}) or {}

    def metric_values(name: str) -> dict:
        """
        k6 --summary-export has changed shape across versions.
        Common patterns:
          metrics.<name>.values.{avg,p(95),count,rate,...}
          metrics.<name>.value (single scalar)
          metrics.<name>.{avg,p(95),count,rate,...} (flat)
        """
        m = metrics.get(name) or {}
        # Newer/alternate format: stats are at the top-level of the metric object.
        if isinstance(m, dict) and (
            "avg" in m
            or "count" in m
            or "rate" in m
            or "p(95)" in m
            or "p(90)" in m
            or "max" in m
            or "min" in m
            or "med" in m
            or "fails" in m
            or "passes" in m
        ):
            return m
        v = m.get("values")
        if isinstance(v, dict):
            return v
        v2 = m.get("value")
        if isinstance(v2, dict):
            return v2
        if v2 is not None:
            return {"value": v2}
        return {}

    # Common high-signal metrics
    http_req_duration = metric_values("http_req_duration")
    http_reqs = metric_values("http_reqs")
    iterations = metric_values("iterations")
    http_req_failed = metric_values("http_req_failed")

    # Some k6 exports store http_req_failed as {passes,fails,value} without "rate".
    if "rate" not in http_req_failed:
        fails = http_req_failed.get("fails")
        passes = http_req_failed.get("passes")
        if isinstance(fails, (int, float)) and isinstance(passes, (int, float)) and (fails + passes) > 0:
            http_req_failed = dict(http_req_failed)
            http_req_failed["rate"] = fails / (fails + passes)

    def fmt(v):
        if v is None:
            return ""
        if isinstance(v, float):
            return f"{v:.4f}"
        return str(v)

    rows = [
        ("http_reqs", "count", fmt(http_reqs.get("count") or http_reqs.get("value"))),
        ("http_reqs", "rate", fmt(http_reqs.get("rate"))),
        ("iterations", "count", fmt(iterations.get("count") or iterations.get("value"))),
        ("iterations", "rate", fmt(iterations.get("rate"))),
        (
            "http_req_failed",
            "rate",
            fmt(http_req_failed.get("rate") or http_req_failed.get("value")),
        ),
        ("http_req_duration", "avg (ms)", fmt(http_req_duration.get("avg"))),
        ("http_req_duration", "p(90) (ms)", fmt(http_req_duration.get("p(90)"))),
        ("http_req_duration", "p(95) (ms)", fmt(http_req_duration.get("p(95)"))),
        ("http_req_duration", "p(99) (ms)", fmt(http_req_duration.get("p(99)"))),
        ("http_req_duration", "max (ms)", fmt(http_req_duration.get("max"))),
        ("http_req_duration", "min (ms)", fmt(http_req_duration.get("min"))),
    ]

    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    title = "k6 Load Test Report"

    html_out = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #111; }}
    h1 {{ margin: 0 0 6px 0; }}
    .meta {{ color: #555; margin-bottom: 16px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background: #f5f5f5; }}
    code {{ background: #f6f8fa; padding: 2px 4px; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>{html.escape(title)}</h1>
  <div class="meta">Generated: {html.escape(now)}<br/>
    Source: <code>{html.escape(in_path)}</code>
  </div>

  <h2>Summary</h2>
  <table>
    <thead>
      <tr><th>Metric</th><th>Field</th><th>Value</th></tr>
    </thead>
    <tbody>
      {''.join(f'<tr><td>{html.escape(m)}</td><td>{html.escape(f)}</td><td>{html.escape(v)}</td></tr>' for m,f,v in rows)}
    </tbody>
  </table>

  <h2>Notes</h2>
  <p>This report is generated from <code>k6 --summary-export</code> JSON and converted to PDF via <code>wkhtmltopdf</code>.</p>

  <h2>Raw exported metrics (debug)</h2>
  <p>If the table above is empty, your k6 version may export different fields. This section shows the raw <code>metrics</code> object.</p>
  <pre style="white-space: pre-wrap; border: 1px solid #ddd; padding: 12px; background: #fafafa;">{html.escape(json.dumps(metrics, indent=2, sort_keys=True)[:200000])}</pre>
</body>
</html>
"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

