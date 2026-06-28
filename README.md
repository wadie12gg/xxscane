<div align="center">

<pre>
 __  __  ____  ____    ____   ___    _    _  _
 \ \/ / / ___|/ ___|  / ___| / __|  / \  | \| |
  >  <  \___ \\___ \  \___ \| (__  / _ \ |    |
 /_/\_\  ____) |___) |  ___) |\___|/_/ \_\|_|\_|
</pre>

# xsscane

**Advanced XSS Detection Suite — crawling, context‑aware fuzzing, WAF evasion & blind (OAST) detection.**

[![CI](https://github.com/wadie12gg/xsscane/actions/workflows/ci.yml/badge.svg)](https://github.com/wadie12gg/xsscane/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Engines](https://img.shields.io/badge/engines-6-orange)
![Tests](https://img.shields.io/badge/tests-41%20passing-brightgreen)
![Free](https://img.shields.io/badge/100%25-free%20%26%20self--hosted-success)

[Features](#-why-xsscane) · [Install](#-quick-start) · [Usage](#-usage) · [Engines](#-detection-engines) · [Reports](#-reports) · [How it works](#-how-it-works) · [Disclaimer](#%EF%B8%8F-disclaimer)

</div>

---

xsscane is a modular, OOP‑designed Cross‑Site Scripting scanner built for professional
security assessments. Instead of blindly firing payloads and grepping the response, it
**analyses the reflection context** with hand‑written parsers, **prunes payloads that
cannot possibly work**, and confirms a finding **only when the executable markup lands
un‑escaped** — a zero‑false‑positive policy. When a WAF blocks a payload, an adaptive
loop **learns** the encoding that gets through.

```text
Confirmed only when this lands un-escaped:
  "><svg onload=alert('xa91f…')>          ← unique canary proves it's real
  </script><img src=x onerror=alert('…')>
  ';alert('…');//                          ← context-correct breakout
```

## ✨ Why xsscane?

|  | Capability |
|--|------------|
| 🔬 | **Six detection engines** — reflected, stored, DOM, DOM‑form, blind/OAST, passive |
| 🎯 | **Zero false positives** — confirms on un‑escaped executable breakout, not mere reflection |
| 🧠 | **Context‑aware fuzzing** — classifies HTML / attribute / script / comment / URI contexts and fires only viable breakouts |
| 🕵️ | **Hidden parameter mining** — Arjun‑style reflection brute‑force uncovers unlinked inputs |
| 🛡️ | **WAF fingerprint + adaptive evasion** — detects 15+ WAFs/CDNs and *learns* what bypasses them |
| 🌐 | **Browser‑first deep crawl** — headless Chromium, SPA state‑machine, XHR/fetch hooks, Bloom‑filter dedup |
| 🔐 | **Stateful auth‑aware navigation** — auto‑detects the login form, re‑authenticates on session drop |
| 📡 | **Blind / out‑of‑band XSS** — self‑hosted OAST listener (Burp‑Collaborator‑style, free) |
| 📑 | **Reports** — JSON · HTML · Markdown · **SARIF** (GitHub code scanning) |
| 🤖 | **Optional local LLM** — offline Ollama assist, **never a paid API** (off by default) |
| 🧪 | **Tested** — 41 unit + end‑to‑end tests, CI on Python 3.10–3.12 |
| 💸 | **100% free & self‑hosted** — no API keys, no quotas, MIT licensed |

## ⚡ Quick Start

```bash
git clone https://github.com/wadie12gg/xsscane.git
cd xsscane

# install the tool (creates the `xsscane` command)
pip install .
playwright install chromium        # browser engine, one-time

# scan a parameterised URL
xsscane -u "https://target.tld/search?q=test"
```

> **Kali / Debian** (PEP 668 managed env): use `pipx install .` or a virtualenv.
> **Dev:** `pip install -e ".[dev]"` then `pytest`.

## 🖥️ Demo

```console
$ xsscane -u "https://xss-game.appspot.com/level1/frame?query=test"

 __  __  ____  ____    ____   ___    _    _  _
 \ \/ / / ___|/ ___|  / ___| / __|  / \  | \| |
  >  <  \___ \\___ \  \___ \| (__  / _ \ |    |
 /_/\_\  ____) |___) |  ___) |\___|/_/ \_\|_|\_|
   v1.0.0  ·  modular XSS detection suite  ·  authorised testing only

[*] Target: https://xss-game.appspot.com/level1/frame?query=test  Modules: reflected
[+] HIGH XSS  ·  reflected  ·  param=query  ·  .../level1/frame?query=test
┌───┬───────────┬───────────┬──────────┬────────────┬──────────────────────────────┐
│ # │ Type      │ Parameter │ Severity │ Confidence │ Payload                      │
├───┼───────────┼───────────┼──────────┼────────────┼──────────────────────────────┤
│ 1 │ reflected │ query     │ HIGH     │ CONFIRMED  │ <script>alert('x15..')</...> │
└───┴───────────┴───────────┴──────────┴────────────┴──────────────────────────────┘
  1 finding(s)  -  1 high severity
```

## 📖 Usage

```bash
# 1) reflected + DOM scan of one URL
xsscane -u "https://target.tld/search?q=test"

# 2) crawl the whole site, then context-aware fuzz every input
xsscane -u "https://target.tld/" --crawl

# 3) uncover hidden parameters first, then scan them
xsscane -u "https://target.tld/page" --mine-params

# 4) authenticated SPA crawl with a self-driving login
xsscane -u "https://app.tld/" --crawl --render \
        --login-url https://app.tld/login --username admin --password s3cret

# 5) blind / out-of-band XSS via a public callback host
xsscane -u "https://target.tld/contact" --blind --oast-url http://YOUR_HOST:8888

# 6) write a SARIF report for GitHub code scanning
xsscane -u "https://target.tld/?q=1" -o report.sarif
```

Run `xsscane -h` for the full, grouped option reference (target & request, crawling &
discovery, authentication, WAF & evasion, OAST, output, network, misc).

| Common flag | Description |
|------|-------------|
| `-u, --url` | Target URL (include parameters to drive reflected/DOM tests) |
| `-t, --type` | Engines to run: `reflected,stored,dom,domform,blind,passive` |
| `--crawl` | Crawl the site, then fuzz every discovered field |
| `--mine-params` | Brute‑force hidden parameters by reflection before fuzzing |
| `--blind --oast-url` | Out‑of‑band (blind) XSS via a self‑hosted listener |
| `--evasion 0‑3` | Mutation aggressiveness (auto‑raised when a WAF is found) |
| `-o, --output` | Write a report (`.json` / `.html` / `.md` / `.sarif`) |
| `--login-url --username --password` | Auto‑authenticate for protected areas |

## 🔬 Detection Engines

| Engine | What it catches | How |
|--------|-----------------|-----|
| **reflected** | Input echoed back in the same response | Profiles surviving breakout chars, fires only viable payloads |
| **stored** | Persisted input rendered later | Submits, re‑fetches the view URL, confirms round‑trip |
| **dom** | Pure client‑side sinks (`innerHTML`, `eval`, …) | Drives Chromium, instruments sinks, confirms on execution |
| **domform** | Client‑side **stored** XSS via forms | Fills + submits in a real browser, watches the sink |
| **blind** | Fires later in someone else's browser | Self‑hosted OAST listener + uniquely‑tokenised payloads |
| **passive** | Missing headers, source→sink flows | One benign GET, payload‑free static survey |

## 📊 Reports

```bash
xsscane -u "https://target.tld/?q=1" -o report.html     # color-coded HTML
xsscane -u "https://target.tld/?q=1" -o report.sarif    # SARIF for CI/CD
```

Every value in the report is HTML‑escaped — **opening the report can never execute the
payloads it documents**. SARIF output drops straight into GitHub **code scanning**.

## 🧠 How It Works

```
        ┌──────────── WAF fingerprint (15+ vendors) ────────────┐
URL ──▶ │  passive pre-pass ──▶ param mining ──▶ crawl/discover  │ ──▶ findings
        │        │                                    │          │
        │   headers + source→sink          context-aware fuzzer  │
        └────────────────────── adaptive evasion loop ───────────┘
```

1. **Fingerprint** the WAF and seed the evasion preference.
2. **Passive** survey (headers + DOM source→sink) — no payloads.
3. **Discover** the attack surface: crawl (browser + static) and **mine hidden parameters**.
4. **Fuzz** each field with context‑correct payloads; confirm only un‑escaped breakouts.
5. **Adapt**: when blocked, try encodings and learn the one that bypasses this WAF.

## 🧪 Tests & CI

```bash
pip install -e ".[dev]"
pytest            # 41 tests: pure-logic units + end-to-end engine integration
```

CI runs the full suite on Python 3.10 / 3.11 / 3.12 on every push and PR.

## 🤝 Contributing

Issues and pull requests are welcome — bug reports, new payloads/contexts, WAF
signatures, or detection engines. Please keep the **zero‑false‑positive** policy and
the **free / self‑hosted** principle (no paid APIs in the core).

## ⚖️ Disclaimer

xsscane is for **authorised security testing and education only**. Use it solely
against systems you own or have **explicit written permission** to test. The built‑in
payloads are benign `alert()` / canary proofs‑of‑concept for detection. The authors
accept **no liability** for misuse or damage. You are responsible for staying within
the law and your engagement scope.

## 📜 License

Released under the [MIT License](LICENSE).

## 👤 Author

**wadiebid** — [@wadie12gg](https://github.com/wadie12gg) · wadiewadie975@gmail.com

<div align="center"><sub>Built for defenders and authorised pentesters. Star ⭐ the repo if it helped you.</sub></div>
