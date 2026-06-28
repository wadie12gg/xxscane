from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanConfig:
    """Immutable-by-convention configuration shared across every scanner module."""

    url: str
    scan_types: list[str] = field(default_factory=lambda: ["reflected", "dom", "domform"])
    method: str = "GET"
    data: Optional[str] = None

    # Transport
    proxy: Optional[str] = None
    cookies: Optional[str] = None
    custom_headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 15.0
    retries: int = 3
    delay: float = 0.0
    rate_limit: float = 0.0       # max requests/sec across the scan (0 = unlimited)
    threads: int = 10
    verify_tls: bool = False

    # Evasion: 0 = raw payloads only, 3 = maximum mutation surface
    evasion_level: int = 2

    # DOM engine
    headless: bool = True

    # Stored-XSS verification endpoint (where submitted data is rendered back)
    stored_view_url: Optional[str] = None

    # Report export
    output: Optional[str] = None
    output_format: str = "auto"   # auto | json | html | md | markdown

    # WAF fingerprinting
    waf_detect: bool = True        # probe for a WAF before scanning
    waf_adapt: bool = True         # raise evasion automatically when a WAF is found
    detected_waf: Optional[str] = None   # filled in after fingerprinting (seeds evasion)

    # Blind / out-of-band (OAST) XSS
    blind: bool = False
    oast_url: Optional[str] = None        # public callback base the target can reach
    oast_listen: str = "0.0.0.0:8888"     # host:port to bind the local listener
    oast_wait: float = 20.0               # seconds to wait for callbacks

    # Hidden parameter discovery (Arjun-style reflection mining)
    mine_params: bool = False

    # Deep discovery + async fuzzing (--deep-scan)
    deep_scan: bool = False
    max_depth: int = 2
    max_pages: int = 200
    concurrency: int = 20
    render: bool = False          # render pages with Playwright to find JS endpoints
    render_limit: int = 25        # cap browser-rendered pages to keep the crawl fast
    max_interactions: int = 12    # state-machine clicks per page (buttons/tabs/etc.)
    jitter_min: float = 0.5       # min throttle delay between page loads (seconds)
    jitter_max: float = 2.0       # max throttle delay between page loads (seconds)

    # Deep navigation engine (stateful SPA exploration)
    deep_nav: bool = False
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    username_selector: str = "input[name=username], input[name=email], input[type=email], #username"
    password_selector: str = "input[type=password], input[name=password], #password"
    submit_selector: str = "button[type=submit], input[type=submit], button"

    # Optional local LLM assist (free, offline, OFF by default — never a paid API)
    llm_assist: bool = False
    llm_endpoint: str = "http://localhost:11434"   # local Ollama server
    llm_model: str = "llama3.2"
    llm_min_confidence: float = 0.6                # consult the model only below this

    verbose: bool = False
