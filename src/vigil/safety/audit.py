"""Append-only audit log.

Every LLM call is recorded (input digest, model, latency, cost, outcome).
This is both a compliance artifact and the engineering proof behind CVP-style
security attestations: *everything is traceable*.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path


def digest(text: str) -> str:
    """Stable sha256 digest of a prompt payload (no raw content is stored)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


class AuditLog:
    """JSONL audit writer. Safe to call from multiple steps."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def record(
        self,
        *,
        event_id: str,
        model: str,
        latency_ms: int,
        cost_usd: float,
        prompt_digest: str,
        ok: bool,
        note: str = "",
    ) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": time.time(),
            "event_id": event_id,
            "model": model,
            "latency_ms": latency_ms,
            "cost_usd": round(cost_usd, 6),
            "prompt_digest": prompt_digest,
            "ok": ok,
            "note": note,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
