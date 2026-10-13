"""Normalized security event model (OCSF-inspired, deliberately small)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class NormalizedEvent(BaseModel):
    """A single normalized security event.

    Field values — especially ``cmdline``, ``file_path`` and anything in
    ``raw`` — MUST be treated as untrusted data by downstream consumers:
    log fields can carry prompt-injection payloads (see ``docs/security-model.md``).
    """

    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: Severity = "info"
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    process: str | None = None
    cmdline: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    def text_fields(self) -> list[str]:
        """String fields that flow into the LLM (after redaction)."""
        return [
            f"host={self.host}",
            f"user={self.user}",
            f"src_ip={self.src_ip}",
            f"dst_ip={self.dst_ip}",
            f"process={self.process}",
            f"cmdline={self.cmdline}",
            f"file_path={self.file_path}",
            f"file_hash={self.file_hash}",
        ]
