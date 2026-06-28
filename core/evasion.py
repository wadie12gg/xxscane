from __future__ import annotations

import logging

from xsscane.core.waf import _BLOCK_PHRASES, _BLOCK_STATUSES
from xsscane.payloads import encoders

# Transforms that change the request signature without breaking a reflected payload
# (a reflected, case-mutated or encoded tag still executes once the app emits it).
_TRANSFORMS = [
    ("case", encoders.case_mutation),
    ("url", encoders.url_encode),
    ("double-url", encoders.double_url_encode),
    ("html-entity", encoders.html_entity_decimal),
    ("html-hex", encoders.html_entity_hex),
    ("unicode", encoders.unicode_overlong),
]

# Starting preference per WAF (a seed); the loop still learns from live feedback.
_WAF_PREFERENCE = {
    "Cloudflare": ["double-url", "unicode", "case"],
    "Akamai": ["double-url", "html-entity", "case"],
    "ModSecurity": ["html-entity", "html-hex", "case"],
    "Imperva Incapsula": ["double-url", "unicode", "case"],
    "F5 BIG-IP ASM": ["html-entity", "double-url", "case"],
}


class AdaptiveEvader:
    """Adaptive WAF evasion: when a payload is blocked, try encoding transforms in
    turn and promote the first that gets through, so the next blocked payload starts
    with it — the engine learns what defeats this specific WAF."""

    def __init__(self, logger: logging.Logger, waf_name: str | None = None):
        self.log = logger
        self._order = list(_TRANSFORMS)
        if waf_name:
            self._seed(waf_name)
        self.blocks = 0
        self.bypasses = 0
        self.preferred: str | None = None

    def _seed(self, waf_name: str) -> None:
        preference = _WAF_PREFERENCE.get(waf_name)
        if not preference:
            return
        rank = {name: i for i, name in enumerate(preference)}
        self._order.sort(key=lambda item: rank.get(item[0], len(preference)))

    @staticmethod
    def is_blocked(status: int | None, body: str | None) -> bool:
        if status in _BLOCK_STATUSES:
            return True
        low = (body or "").lower()
        return any(phrase in low for phrase in _BLOCK_PHRASES)

    def variants(self, value: str) -> list[tuple[str, str]]:
        out = []
        for name, transform in self._order:
            try:
                transformed = transform(value)
            except Exception:
                continue
            if transformed and transformed != value:
                out.append((name, transformed))
        return out

    def learn(self, name: str) -> None:
        self.bypasses += 1
        self.preferred = name
        # Stable promotion: the winning transform moves to the front, rest unchanged.
        self._order.sort(key=lambda item: 0 if item[0] == name else 1)
