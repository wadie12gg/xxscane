from __future__ import annotations

# Structural characters that decide whether an XSS breakout is even possible.
# If, say, `<` is stripped or HTML-encoded at the reflection point, no tag-based
# payload can ever fire there — so there is no point spending requests on it.
PROBE_CHARS = "<>\"'`/;"


def survival_marker(token: str) -> str:
    """Fence the probe characters between two copies of the token so the survivors
    can be read back unambiguously, without bleeding into adjacent page markup."""
    return f"{token}{PROBE_CHARS}{token}"


def surviving_chars(body: str, token: str) -> set[str]:
    """Which probe characters came back un-encoded between the two token fences."""
    first = body.find(token)
    if first == -1:
        return set()
    start = first + len(token)
    end = body.find(token, start)
    region = body[start:end] if end != -1 else body[start:start + 16]
    return {c for c in PROBE_CHARS if c in region}


def required_chars(value: str) -> set[str]:
    return {c for c in value if c in PROBE_CHARS}


def select(payloads, surviving: set[str]):
    """Occurrence/efficiency ordering: keep only payloads whose structural characters
    all survive, smallest footprint first (minimal payloads bypass signature WAFs
    more often). If we have no positive survival signal, don't filter — never trade
    a real detection for a micro-optimisation."""
    if not surviving:
        return list(payloads)
    viable = []
    for index, payload in enumerate(payloads):
        required = required_chars(payload.decoded)
        if required.issubset(surviving):
            viable.append((len(required), index, payload))
    viable.sort(key=lambda item: (item[0], item[1]))
    return [payload for _, _, payload in viable]
