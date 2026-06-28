from __future__ import annotations

import base64
import random
import re
import urllib.parse

# Tokens that represent HTML structure (tag and attribute names). Mutating only
# these keeps the surrounding JavaScript — which is case-sensitive — intact.
_HTML_TOKEN = re.compile(
    r"</?\s*[a-zA-Z][a-zA-Z0-9]*|\b(?:on[a-z]+|src|href|style|data|formaction)\b",
    re.IGNORECASE,
)


def url_encode(payload: str) -> str:
    return urllib.parse.quote(payload, safe="")


def double_url_encode(payload: str) -> str:
    # Edge filters frequently decode once and inspect the result; a second pass of
    # decoding happens at the application layer, so the live payload slips past.
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def html_entity_decimal(payload: str) -> str:
    return "".join(f"&#{ord(c)};" for c in payload)


def html_entity_hex(payload: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in payload)


def js_hex_escape(payload: str) -> str:
    return "".join(f"\\x{ord(c):02x}" for c in payload)


def js_unicode_escape(payload: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in payload)


def unicode_overlong(payload: str) -> str:
    # Full-width homoglyph substitution. Signature engines match on the raw ASCII
    # bytes, while a Unicode-normalising sink (NFKC) folds these back to '<', '>'
    # and friends after inspection has already passed.
    table = {chr(c): chr(c + 0xFEE0) for c in range(0x21, 0x7F)}
    return "".join(table.get(c, c) for c in payload)


def base64_eval(payload: str) -> str:
    blob = base64.b64encode(payload.encode()).decode()
    return f"eval(atob('{blob}'))"


def case_mutation(payload: str) -> str:
    def flip(match: re.Match) -> str:
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in match.group())

    return _HTML_TOKEN.sub(flip, payload)
