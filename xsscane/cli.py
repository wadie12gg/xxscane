from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from xsscane.core.config import ScanConfig
from xsscane.core.scanner import Scanner
from xsscane.utils.logger import console
from xsscane.utils.reporter import print_banner, print_report


class _HelpFormatter(argparse.RawDescriptionHelpFormatter,
                     argparse.ArgumentDefaultsHelpFormatter):
    """Show each option's default value *and* preserve the example block layout."""


_EXAMPLES = """\
examples:
  # reflected + DOM scan of one parameterised URL
  xsscane -u "https://target.tld/search?q=test"

  # crawl the whole site, then context-aware fuzz every input
  xsscane -u "https://target.tld/" --crawl

  # authenticated SPA crawl with a self-driving login
  xsscane -u "https://app.tld/" --crawl --render \\
          --login-url https://app.tld/login --username admin --password s3cret

  # blind / out-of-band XSS via a public callback host
  xsscane -u "https://target.tld/contact" --blind --oast-url http://YOUR_HOST:8888

  # SARIF report for GitHub code scanning
  xsscane -u "https://target.tld/?q=1" -o report.sarif

Authorised security testing only. See the README disclaimer.
"""


def _load_config_file(path: str, parser: argparse.ArgumentParser) -> dict:
    """Load defaults from a YAML/JSON config file. Keys are CLI option names
    (e.g. `evasion`, `max_depth`, `no_waf_detect`); CLI flags still override them."""
    text = Path(path).read_text(encoding="utf-8-sig")  # tolerate a BOM (common on Windows)
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError:
            raise SystemExit("PyYAML is needed for YAML configs (pip install pyyaml) — or use a .json file.")
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise SystemExit("Config file must be a mapping of option: value.")

    valid = {action.dest for action in parser._actions} - {"help", "config"}
    filtered, unknown = {}, []
    for key, value in data.items():
        dest = str(key).replace("-", "_")
        (filtered.__setitem__(dest, value) if dest in valid else unknown.append(key))
    if unknown:
        console.print(f"[warning]Ignoring unknown config keys: {', '.join(map(str, unknown))}[/]")
    return filtered


def parse_args(argv=None) -> argparse.Namespace:
    if argv is None:
        argv = sys.argv[1:]
    parser = argparse.ArgumentParser(
        prog="xsscane",
        usage="xsscane -u URL [options]",
        description=(
            "xsscane — modular XSS detection suite: site crawling, context-aware "
            "fuzzing, WAF fingerprinting & evasion, and blind (out-of-band) detection."
        ),
        epilog=_EXAMPLES,
        formatter_class=_HelpFormatter,
    )

    target = parser.add_argument_group("target & request")
    target.add_argument("-u", "--url", metavar="URL",
                        help="Target URL (include parameters to drive reflected/DOM tests)")
    target.add_argument("-t", "--type", metavar="LIST", default="reflected,dom,domform",
                        help="Comma-separated scan types: reflected,stored,dom,domform,blind,passive")
    target.add_argument("-m", "--method", default="GET", choices=["GET", "POST"],
                        help="HTTP method for parameter injection")
    target.add_argument("-d", "--data", metavar="BODY", help="POST body, e.g. 'q=test&page=1'")
    target.add_argument("--proxy", metavar="URL", help="Proxy URL, e.g. http://127.0.0.1:8080")
    target.add_argument("--cookies", metavar="STR",
                        help="Cookie header value for authenticated scans")
    target.add_argument("-H", "--header", action="append", default=[], metavar="K:V",
                        help="Extra request header (repeatable)")
    target.add_argument("--stored-view-url", metavar="URL",
                        help="URL where stored payloads are rendered back (stored scan)")

    disc = parser.add_argument_group("crawling & discovery")
    disc.add_argument("--crawl", "--deep-scan", dest="deep_scan", action="store_true",
                      help="Crawl the whole site, then context-aware fuzz every field")
    disc.add_argument("--mine-params", action="store_true",
                      help="Brute-force hidden parameters by reflection (Arjun-style) before fuzzing")
    disc.add_argument("--max-depth", type=int, default=2, metavar="N", help="Maximum crawl depth")
    disc.add_argument("--max-pages", type=int, default=200, metavar="N",
                      help="Maximum pages to crawl")
    disc.add_argument("--concurrency", type=int, default=20, metavar="N",
                      help="Async concurrent requests")
    disc.add_argument("--render", action="store_true",
                      help="Render pages with Playwright (network-idle) to find JS endpoints")
    disc.add_argument("--render-limit", type=int, default=25, metavar="N",
                      help="Maximum pages to render with the browser")
    disc.add_argument("--max-interactions", type=int, default=12, metavar="N",
                      help="State-machine clicks per page (buttons/tabs/dropdowns)")
    disc.add_argument("--jitter-min", type=float, default=0.5, metavar="SEC",
                      help="Minimum throttle delay between page loads (seconds)")
    disc.add_argument("--jitter-max", type=float, default=2.0, metavar="SEC",
                      help="Maximum throttle delay between page loads (seconds)")

    auth = parser.add_argument_group("authentication (stateful navigation)")
    auth.add_argument("--deep-nav", action="store_true",
                      help="Explore SPA application states by interacting with the DOM")
    auth.add_argument("--login-url", metavar="URL", help="Login page URL for auth-aware navigation")
    auth.add_argument("--username", metavar="STR", help="Username/email for auto re-authentication")
    auth.add_argument("--password", metavar="STR", help="Password for auto re-authentication")
    auth.add_argument("--username-selector", metavar="CSS", help="CSS selector for the username field")
    auth.add_argument("--password-selector", metavar="CSS", help="CSS selector for the password field")
    auth.add_argument("--submit-selector", metavar="CSS", help="CSS selector for the login submit button")
    auth.add_argument("--llm-assist", action="store_true",
                      help="Use a LOCAL Ollama model to resolve ambiguous auth states "
                           "(free, offline, off by default)")
    auth.add_argument("--llm-endpoint", metavar="URL", default="http://localhost:11434",
                      help="Local Ollama endpoint for --llm-assist")
    auth.add_argument("--llm-model", metavar="NAME", default="llama3.2",
                      help="Local model name for --llm-assist")

    waf = parser.add_argument_group("WAF & evasion")
    waf.add_argument("--evasion", type=int, default=2, choices=[0, 1, 2, 3], metavar="0-3",
                     help="Evasion aggressiveness: 0=raw, 3=maximum mutation")
    waf.add_argument("--no-waf-detect", action="store_true",
                     help="Skip the WAF fingerprinting probe")
    waf.add_argument("--no-waf-adapt", action="store_true",
                     help="Do not auto-raise evasion when a WAF is detected")

    oast = parser.add_argument_group("blind / out-of-band XSS (OAST)")
    oast.add_argument("--blind", action="store_true",
                      help="Detect blind/stored XSS via out-of-band callbacks (needs --oast-url)")
    oast.add_argument("--oast-url", metavar="URL",
                      help="Public callback base URL the target can reach, e.g. http://your-host:8888")
    oast.add_argument("--oast-listen", default="0.0.0.0:8888", metavar="HOST:PORT",
                      help="host:port to bind the local OAST listener")
    oast.add_argument("--oast-wait", type=float, default=20.0, metavar="SEC",
                      help="Seconds to wait for out-of-band callbacks")

    out = parser.add_argument_group("output & reporting")
    out.add_argument("-o", "--output", metavar="FILE",
                     help="Write findings to a file (.json/.html/.md/.sarif)")
    out.add_argument("--format", dest="output_format", default="auto",
                     choices=["auto", "json", "html", "md", "markdown", "sarif"],
                     help="Report format (default: infer from --output extension)")

    net = parser.add_argument_group("network & performance")
    net.add_argument("--threads", type=int, default=10, metavar="N", help="Concurrent workers")
    net.add_argument("--timeout", type=float, default=15.0, metavar="SEC",
                     help="Per-request timeout (s)")
    net.add_argument("--retries", type=int, default=3, metavar="N", help="Connection retry attempts")
    net.add_argument("--delay", type=float, default=0.0, metavar="SEC",
                     help="Delay between requests (s)")
    net.add_argument("--rate", type=float, default=0.0, metavar="RPS",
                     help="Max requests per second (0 = unlimited); honours Retry-After on 429")

    misc = parser.add_argument_group("misc")
    misc.add_argument("--config", metavar="FILE",
                      help="Load options from a YAML/JSON file (CLI flags override)")
    misc.add_argument("--no-headless", action="store_true",
                      help="Show the browser window during DOM scans")
    misc.add_argument("--verify-tls", action="store_true",
                      help="Enforce TLS certificate verification (off by default)")
    misc.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logging")
    misc.add_argument("-V", "--version", action="store_true", help="Print the version and exit")

    # Config-file values become defaults; explicit CLI flags still win.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config")
    known, _ = pre.parse_known_args(argv)
    if known.config:
        parser.set_defaults(**_load_config_file(known.config, parser))

    args = parser.parse_args(argv)
    if args.version:
        from xsscane import __version__
        print(f"xsscane {__version__}")
        raise SystemExit(0)
    if not args.url:
        parser.error("a target URL is required (pass -u/--url or set 'url' in --config)")
    return args


def build_config(args: argparse.Namespace) -> ScanConfig:
    headers: dict[str, str] = {}
    for raw in args.header:
        if ":" in raw:
            key, value = raw.split(":", 1)
            headers[key.strip()] = value.strip()

    config = ScanConfig(
        url=args.url,
        scan_types=[t.strip() for t in args.type.split(",") if t.strip()],
        method=args.method,
        data=args.data,
        proxy=args.proxy,
        cookies=args.cookies,
        custom_headers=headers,
        stored_view_url=args.stored_view_url,
        output=args.output,
        output_format=args.output_format,
        waf_detect=not args.no_waf_detect,
        waf_adapt=not args.no_waf_adapt,
        blind=args.blind,
        oast_url=args.oast_url,
        oast_listen=args.oast_listen,
        oast_wait=args.oast_wait,
        evasion_level=args.evasion,
        mine_params=args.mine_params,
        deep_scan=args.deep_scan,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        concurrency=args.concurrency,
        render=args.render,
        render_limit=args.render_limit,
        max_interactions=args.max_interactions,
        jitter_min=args.jitter_min,
        jitter_max=args.jitter_max,
        deep_nav=args.deep_nav,
        login_url=args.login_url,
        username=args.username,
        password=args.password,
        llm_assist=args.llm_assist,
        llm_endpoint=args.llm_endpoint,
        llm_model=args.llm_model,
        threads=args.threads,
        timeout=args.timeout,
        retries=args.retries,
        delay=args.delay,
        rate_limit=args.rate,
        headless=not args.no_headless,
        verify_tls=args.verify_tls,
        verbose=args.verbose,
    )

    # Apply login selector overrides only when supplied (keep the sensible defaults).
    for attr in ("username_selector", "password_selector", "submit_selector"):
        value = getattr(args, attr)
        if value:
            setattr(config, attr, value)

    # Enable the blind engine whenever OAST is requested.
    if (args.blind or args.oast_url) and "blind" not in config.scan_types:
        config.scan_types.append("blind")
    return config


def main(argv=None) -> int:
    args = parse_args(argv)
    print_banner()
    config = build_config(args)

    if config.waf_detect:
        from xsscane.core.waf import WafFingerprinter
        from xsscane.utils.reporter import print_waf_result

        waf = WafFingerprinter(config).fingerprint()
        print_waf_result(waf)
        if waf.detected:
            config.detected_waf = waf.name  # seeds the adaptive evasion preference
            if config.waf_adapt and config.evasion_level < 3:
                config.evasion_level = 3
                console.print(f"[info]Auto-raised evasion to 3 to counter {waf.name}[/]")

    try:
        if config.deep_scan:
            # Imported lazily so the default scan never needs httpx / bs4 installed.
            from xsscane.core.deep_engine import DeepScanEngine

            findings = DeepScanEngine(config).run()
        else:
            findings = Scanner(config).run()
    except KeyboardInterrupt:
        console.print("\n[warning]Scan interrupted by user[/]")
        return 130
    print_report(findings, config.url)

    if config.output:
        from xsscane.utils.exporter import export_findings

        try:
            fmt = export_findings(findings, config.output, config.output_format, config.url)
            console.print(f"[success]Report written:[/] {config.output} ({fmt})")
        except Exception as exc:
            console.print(f"[danger]Failed to write report: {exc}[/]")

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
