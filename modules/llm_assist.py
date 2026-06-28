from __future__ import annotations

import hashlib
import json
import logging

import httpx


class LocalLLMClassifier:
    """Optional, offline auth-state classifier backed by a *local* Ollama model.
    Never makes a paid or remote API call — talks only to a local endpoint (default
    http://localhost:11434); if unreachable it degrades silently to the heuristics.
    The page digest sent excludes input *values*, so no typed secret leaves the
    browser; the model only proposes, the caller validates against the known states."""

    VALID_STATES = (
        "anonymous", "login_page", "authenticated", "expired",
        "mfa_required", "captcha", "blocked", "unknown",
    )

    def __init__(self, endpoint: str, model: str, logger: logging.Logger, timeout: float = 20.0):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.log = logger
        self.timeout = timeout
        self._cache: dict[str, tuple | None] = {}
        self._checked = False
        self._available = False

    async def available(self) -> bool:
        """Probe the local endpoint once; cache the result. A failure is not an
        error — it just means we fall back to heuristics (still free, no API)."""
        if self._checked:
            return self._available
        self._checked = True
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.endpoint}/api/tags")
                self._available = response.status_code == 200
        except Exception:
            self._available = False

        if self._available:
            self.log.info(f"[info]LLM assist online (local '{self.model}' @ {self.endpoint})[/]")
        else:
            self.log.warning(
                f"[warning]--llm-assist set but no local model reachable at {self.endpoint}; "
                f"continuing with heuristics only (free, no API). Start Ollama to enable it.[/]"
            )
        return self._available

    async def classify(self, digest: dict) -> tuple[str, float, str] | None:
        """Return (state, confidence, reason) or None. Results are cached per digest
        so repeated identical pages cost nothing."""
        key = hashlib.blake2b(json.dumps(digest, sort_keys=True).encode("utf-8", "ignore"),
                              digest_size=16).hexdigest()
        if key in self._cache:
            return self._cache[key]

        verdict = None
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.endpoint}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": self._build_prompt(digest),
                        "stream": False,
                        "format": "json",
                        "options": {"temperature": 0},
                    },
                )
                response.raise_for_status()
                verdict = self._parse(response.json().get("response", ""))
        except Exception as exc:
            self.log.debug(f"[muted]LLM assist call failed: {exc}[/]")

        self._cache[key] = verdict
        return verdict

    def _build_prompt(self, digest: dict) -> str:
        return (
            "You classify the authentication state of a web page for an AUTHORISED "
            "security scan. Do NOT generate, guess, or request credentials - only "
            "classify what the page shows.\n"
            f"Valid states: {', '.join(self.VALID_STATES)}.\n"
            'Respond with ONLY a JSON object: '
            '{"state": <one valid state>, "confidence": <0..1>, "reason": <short>}.\n\n'
            f"PAGE DIGEST:\n{json.dumps(digest)[:4000]}"
        )

    def _parse(self, raw: str) -> tuple[str, float, str] | None:
        try:
            data = json.loads(raw)
        except Exception:
            return None
        state = str(data.get("state", "")).lower().strip()
        if state not in self.VALID_STATES:
            return None
        try:
            confidence = max(0.0, min(1.0, float(data.get("confidence", 0))))
        except (TypeError, ValueError):
            confidence = 0.0
        reason = str(data.get("reason", ""))[:80]
        return state, confidence, reason
