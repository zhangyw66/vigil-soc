"""Runtime configuration.

Every knob is overridable through ``VIGIL_*`` environment variables so the tool
stays local-first and deployable in air-gapped environments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    return float(value) if value is not None else default


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value is not None else default


def _env_path(name: str, default: str) -> Path | None:
    value = os.getenv(name)
    return Path(value) if value else Path(default)


@dataclass(frozen=True)
class Settings:
    """Global settings. Values are resolved once at import time."""

    # --- LLM provider ---
    provider: str = field(default_factory=lambda: os.getenv("VIGIL_PROVIDER", "stub"))
    claude_model: str = field(
        default_factory=lambda: os.getenv("VIGIL_CLAUDE_MODEL", "claude-sonnet-5-5")
    )
    claude_max_tokens: int = field(default_factory=lambda: _env_int("VIGIL_CLAUDE_MAX_TOKENS", 1024))
    ollama_url: str = field(
        default_factory=lambda: os.getenv("VIGIL_OLLAMA_URL", "http://localhost:11434")
    )

    # --- hybrid scoring fusion ---
    w_deterministic: float = field(default_factory=lambda: _env_float("VIGIL_W_DET", 0.4))
    w_llm: float = field(default_factory=lambda: _env_float("VIGIL_W_LLM", 0.6))
    benign_cutoff: float = field(default_factory=lambda: _env_float("VIGIL_BENIGN_CUTOFF", 30.0))
    malicious_cutoff: float = field(default_factory=lambda: _env_float("VIGIL_MALICIOUS_CUTOFF", 70.0))
    escalation_delta: float = field(default_factory=lambda: _env_float("VIGIL_ESCALATION_DELTA", 25.0))

    # --- pipeline behavior ---
    redact: bool = field(default_factory=lambda: _env_bool("VIGIL_REDACT", True))
    audit_dir: Path = field(default_factory=lambda: Path(os.getenv("VIGIL_AUDIT_DIR", ".vigil/audit")))
    ti_file: Path | None = field(
        default_factory=lambda: _env_path("VIGIL_TI_FILE", ".vigil/ti.json")
    )

    @property
    def audit_path(self) -> Path:
        return self.audit_dir / "audit.jsonl"


# Module-level singleton; tests may construct their own Settings.
settings = Settings()
