from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from xsscane.core.models import Finding, Severity

_SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}

_CSS = """
body{font-family:system-ui,'Segoe UI',Arial,sans-serif;margin:2rem;color:#1b1b1b;background:#fafafa}
h1{margin:0 0 .25rem}
.meta{color:#666;font-size:.9rem;margin:.25rem 0 1rem}
.chip{display:inline-block;padding:.15rem .55rem;border-radius:1rem;margin:0 .4rem .4rem 0;font-size:.8rem;color:#fff}
.chip.high{background:#c0392b}.chip.medium{background:#e67e22}.chip.low{background:#2980b9}.chip.info{background:#7f8c8d}
table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1)}
th,td{border:1px solid #e6e6e6;padding:.5rem .6rem;text-align:left;vertical-align:top;font-size:.85rem}
th{background:#34495e;color:#fff;position:sticky;top:0}
code{background:#f3f3f3;padding:.1rem .3rem;border-radius:3px;word-break:break-all}
td.url{max-width:280px;word-break:break-all;color:#555}
.sev{font-weight:700;padding:.1rem .4rem;border-radius:3px;color:#fff}
.sev.high{background:#c0392b}.sev.medium{background:#e67e22}.sev.low{background:#2980b9}.sev.info{background:#7f8c8d}
tr:nth-child(even){background:#fbfbfb}
"""


def export_findings(findings: list[Finding], path: str, fmt: str, target: str) -> str:
    """Write findings to `path` in the chosen format and return the resolved format."""
    fmt = (fmt or "auto").lower()
    if fmt == "auto":
        fmt = _infer_format(path)
    if fmt == "json":
        content = to_json(findings, target)
    elif fmt in ("md", "markdown"):
        content = to_markdown(findings, target)
    elif fmt in ("html", "htm"):
        content = to_html(findings, target)
    elif fmt == "sarif":
        content = to_sarif(findings, target)
    else:
        raise ValueError(f"Unsupported report format: {fmt}")
    Path(path).write_text(content, encoding="utf-8")
    return fmt


def _infer_format(path: str) -> str:
    return {
        ".json": "json", ".md": "markdown", ".markdown": "markdown",
        ".html": "html", ".htm": "html", ".sarif": "sarif",
    }.get(Path(path).suffix.lower(), "json")


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    return counts


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def to_json(findings: list[Finding], target: str) -> str:
    payload = {
        "tool": "XSScan",
        "target": target,
        "generated_at": _timestamp(),
        "total": len(findings),
        "severity_counts": _severity_counts(findings),
        "findings": [
            {
                "scanner": f.scanner,
                "url": f.url,
                "parameter": f.parameter,
                "method": f.method,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "payload": f.payload,
                "evidence": f.evidence,
            }
            for f in _sorted(findings)
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# SARIF severity → level mapping for code-scanning dashboards.
_SARIF_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning",
                Severity.LOW: "note", Severity.INFO: "note"}


def to_sarif(findings: list[Finding], target: str) -> str:
    """SARIF 2.1.0 — consumable by GitHub code scanning and other CI/CD tools."""
    rule_ids = sorted({f.scanner for f in findings})
    results = []
    for finding in _sorted(findings):
        results.append({
            "ruleId": f"xss/{finding.scanner}",
            "level": _SARIF_LEVEL.get(finding.severity, "note"),
            "message": {"text": f"{finding.severity.value} XSS in '{finding.parameter}' "
                                f"({finding.confidence.value}): {finding.evidence}. "
                                f"Payload: {finding.payload}"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": finding.url}}
            }],
            "properties": {"parameter": finding.parameter, "method": finding.method,
                           "confidence": finding.confidence.value},
        })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "xsscane",
                "informationUri": "https://github.com/wadie12gg/xsscane",
                "rules": [{"id": f"xss/{rid}", "name": f"{rid}-xss",
                           "shortDescription": {"text": f"{rid} XSS"}} for rid in rule_ids],
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def to_markdown(findings: list[Finding], target: str) -> str:
    cell = lambda s: (s or "").replace("|", "\\|").replace("\n", " ")
    lines = [
        "# XSS Scan Report",
        "",
        f"- **Target:** {target}",
        f"- **Generated:** {_timestamp()}",
        f"- **Total findings:** {len(findings)}",
    ]
    counts = _severity_counts(findings)
    if counts:
        lines.append("- **By severity:** " + ", ".join(f"{k}: {v}" for k, v in counts.items()))
    if not findings:
        lines += ["", "_No XSS vulnerabilities detected._", ""]
        return "\n".join(lines)

    lines += [
        "",
        "| # | Type | Severity | Confidence | Method | Parameter | Payload | Evidence | URL |",
        "|---|------|----------|------------|--------|-----------|---------|----------|-----|",
    ]
    for index, f in enumerate(_sorted(findings), 1):
        row = [str(index), f.scanner, f.severity.value, f.confidence.value, f.method,
               cell(f.parameter), f"`{cell(f.payload)}`", cell(f.evidence), cell(f.url)]
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"


def to_html(findings: list[Finding], target: str) -> str:
    # Every dynamic value is HTML-escaped so opening the report can never execute
    # the very payloads it documents — the report itself must not be an XSS vector.
    esc = html.escape
    counts = _severity_counts(findings)
    chips = "".join(
        f'<span class="chip {k.lower()}">{esc(k)}: {v}</span>' for k, v in counts.items()
    )
    rows = []
    for index, f in enumerate(_sorted(findings), 1):
        sev = f.severity.value
        rows.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td>{esc(f.scanner)}</td>"
            f'<td><span class="sev {sev.lower()}">{esc(sev)}</span></td>'
            f"<td>{esc(f.confidence.value)}</td>"
            f"<td>{esc(f.method)}</td>"
            f"<td>{esc(f.parameter)}</td>"
            f"<td><code>{esc(f.payload)}</code></td>"
            f"<td>{esc(f.evidence)}</td>"
            f'<td class="url">{esc(f.url)}</td>'
            "</tr>"
        )
    body = "\n".join(rows) or '<tr><td colspan="9">No XSS vulnerabilities detected.</td></tr>'
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
        f"<title>XSS Scan Report - {esc(target)}</title>\n"
        f"<style>{_CSS}</style></head><body>\n"
        "<h1>XSS Scan Report</h1>\n"
        f'<p class="meta">Target: <code>{esc(target)}</code> &middot; Generated: {_timestamp()} '
        f"&middot; Total findings: {len(findings)}</p>\n"
        f"<p>{chips}</p>\n"
        "<table><thead><tr>"
        "<th>#</th><th>Type</th><th>Severity</th><th>Confidence</th><th>Method</th>"
        "<th>Parameter</th><th>Payload</th><th>Evidence</th><th>URL</th>"
        "</tr></thead><tbody>\n"
        f"{body}\n"
        "</tbody></table>\n</body></html>\n"
    )
