import json

from xsscane.core.models import Confidence, Finding, Severity
from xsscane.utils import exporter

FINDINGS = [
    Finding("fuzzer", "http://t/p?q=1", "q", "1<svg onload=alert('x')>",
            Severity.HIGH, Confidence.CONFIRMED, "html breakout", "GET"),
    Finding("reflected", "http://t/s?n=a", "n", 'a"><img src=x onerror=alert(1)>',
            Severity.LOW, Confidence.POSSIBLE, "filtered", "GET"),
]


def test_json_structure():
    data = json.loads(exporter.to_json(FINDINGS, "http://t/"))
    assert data["total"] == 2 and data["severity_counts"]["HIGH"] == 1
    assert data["findings"][0]["severity"] == "HIGH"  # sorted: HIGH first


def test_html_escapes_payloads():
    # Security-critical: opening the report must never execute the payloads.
    out = exporter.to_html(FINDINGS, "http://t/")
    assert "<svg onload=alert" not in out and "&lt;svg onload=alert" in out
    assert "<img src=x onerror" not in out


def test_markdown_table():
    md = exporter.to_markdown(FINDINGS, "http://t/")
    assert "| # | Type |" in md and "onload=alert" in md


def test_sarif_2_1_0():
    sarif = json.loads(exporter.to_sarif(FINDINGS, "http://t/"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "xsscane"
    first = run["results"][0]
    assert first["level"] == "error"  # HIGH -> error
    assert first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "http://t/p?q=1"


def test_empty_render_is_clean():
    assert "No XSS vulnerabilities detected" in exporter.to_html([], "http://t/")
    assert "No XSS vulnerabilities detected" in exporter.to_markdown([], "http://t/")
