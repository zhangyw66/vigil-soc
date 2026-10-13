"""LLM providers.

First-class provider is Anthropic (Claude). A deterministic ``stub`` provider
enables offline development, tests, and CI without any API key. An optional
Ollama provider covers air-gapped/offline deployments.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Protocol

from vigil.config import Settings


@dataclass
class LLMResult:
    text: str
    model: str
    latency_ms: int = 0
    cost_usd: float = 0.0  # set to 0.0 unless billing data is configured


class LLMProvider(Protocol):
    model: str

    def complete(self, system: str, user: str) -> LLMResult:
        """Complete a single assistant turn."""
        ...


class StubProvider:
    """Deterministic offline provider used for tests, CI and demos.

    It reads the framed event, runs cheap heuristics, and returns a
    schema-valid triage object — so the whole pipeline is exercisable with
    zero network access.
    """

    model = "stub"

    _SUSPICIOUS_TOKENS = (
        "-enc",
        "-encodedcommand",
        "frombase64string",
        "mimikatz",
        "wscript",
        "mshta",
        "certutil -urlcache",
        "schtasks /create",
        "schtasks.exe /create",
        "whoami /priv",
    )

    def complete(self, system: str, user: str) -> LLMResult:
        import re  # noqa: PLC0415

        start = time.monotonic()
        data: dict = {}
        match = re.search(r"<event_data>\s*(.*?)\s*</event_data>", user, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(1))
            except json.JSONDecodeError:
                data = {}
        cmdline = str(data.get("cmdline") or "")
        event_type = str(data.get("event_type") or "")
        lowered = cmdline.lower()
        hits = [t for t in self._SUSPICIOUS_TOKENS if t in lowered]
        strong_hits = [
            t
            for t in (
                "-enc", "-encodedcommand", "frombase64string",
                "schtasks /create", "schtasks.exe /create",
            )
            if t in lowered
        ]
        reasons = []
        if strong_hits:
            score = 78.0
            reasons = [
                {
                    "claim": "encoded/obfuscated command or persistence setup (strong signal)",
                    "source_ref": "event.cmdline",
                    "kind": "llm_inference",
                }
            ]
        elif hits:
            score = min(85.0, 50.0 + 12.0 * len(hits))
            reasons = [
                {
                    "claim": f"command line contains suspicious token(s): {', '.join(hits)}",
                    "source_ref": "event.cmdline",
                    "kind": "llm_inference",
                }
            ]
        elif event_type in {"user_logon", "file_access"}:
            score = 18.0
            reasons = [{
                "claim": "routine operational event type",
                "source_ref": "event.event_type",
                "kind": "llm_inference",
            }]
        else:
            score = 25.0
            reasons = [{
                "claim": "no strong signal; low-to-moderate suspicion by default",
                "source_ref": "event.event_type",
                "kind": "llm_inference",
            }]
        verdict = "MALICIOUS" if score >= 70 else ("SUSPICIOUS" if score >= 30 else "BENIGN")
        text = json.dumps(
            {
                "verdict": verdict,
                "confidence": round(0.5 + abs(score - 50) / 100, 2),
                "llm_score": round(score, 1),
                "reasons": reasons,
                "mitre_attack": ["T1059.001"] if hits else [],
                "iocs": [],
            }
        )
        return LLMResult(text=text, model=self.model, latency_ms=int((time.monotonic() - start) * 1000))


class AnthropicProvider:
    """Claude provider via the official ``anthropic`` SDK (optional extra)."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.model = settings.claude_model

    def complete(self, system: str, user: str) -> LLMResult:
        try:
            import anthropic  # noqa: PLC0415 - optional dependency
        except ImportError as exc:
            raise RuntimeError(
                "anthropic SDK is not installed; run `pip install vigil-soc[claude]`"
            ) from exc
        client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
        start = time.monotonic()
        response = client.messages.create(
            model=self.model,
            max_tokens=self.settings.claude_max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        latency = int((time.monotonic() - start) * 1000)
        text = "".join(
            block.text for block in response.content if getattr(block, "type", "") == "text"
        )
        return LLMResult(text=text, model=self.model, latency_ms=latency)


class OllamaProvider:
    """Local Ollama provider for air-gapped deployments."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.model = "qwen2.5:7b"

    def complete(self, system: str, user: str) -> LLMResult:
        import httpx  # noqa: PLC0415

        start = time.monotonic()
        resp = httpx.post(
            f"{self.settings.ollama_url}/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "format": "json",
            },
            timeout=120.0,
        )
        resp.raise_for_status()
        latency = int((time.monotonic() - start) * 1000)
        return LLMResult(
            text=resp.json().get("message", {}).get("content", ""),
            model=self.model,
            latency_ms=latency,
        )


def get_provider(name: str, settings: Settings) -> LLMProvider:
    normalized = (name or settings.provider).strip().lower()
    if normalized in {"", "stub"}:
        return StubProvider()
    if normalized in {"anthropic", "claude"}:
        return AnthropicProvider(settings)
    if normalized in {"ollama", "local"}:
        return OllamaProvider(settings)
    raise ValueError(f"unknown provider {name!r}; use stub|anthropic|ollama")
