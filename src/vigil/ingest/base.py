"""Connector protocol and shared helpers."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from vigil.models.event import NormalizedEvent


class IngestError(Exception):
    """Raised when a connector cannot do its job."""


def parse_ts(value: str | int | float | None) -> datetime:
    """Parse ISO-8601 or epoch (seconds/ms) timestamps leniently."""
    if value is None:
        raise ValueError("missing timestamp")
    if isinstance(value, (int, float)):
        v = float(value)
        return datetime.fromtimestamp(v / 1000 if v > 10_000_000_000 else v)
    text = str(value).strip()
    if text.isdigit():
        return parse_ts(int(text))
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


@runtime_checkable
class Connector(Protocol):
    """A data-source connector.

    Implementations MUST treat every field as untrusted data and MUST NOT
    interpret field values as instructions.
    """

    name: str

    def load(self, source: Path) -> tuple[list[NormalizedEvent], list[str]]:
        """Load events and a list of human-readable parse errors."""
        ...
