"""Shared test helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from vigil.config import Settings
from vigil.models.event import NormalizedEvent


def make_event(**overrides) -> NormalizedEvent:
    base: dict = {
        "event_id": "evt-test-001",
        "timestamp": datetime(2026, 10, 1, 8, 0, tzinfo=UTC),
        "source": "edr",
        "event_type": "process_start",
        "severity": "medium",
        "host": "host-01",
        "user": "alice",
        "src_ip": "10.0.0.5",
        "dst_ip": "198.51.100.7",
        "dst_port": 443,
        "process": "powershell.exe",
        "cmdline": "powershell.exe -nop -w hidden",
    }
    base.update({k: v for k, v in overrides.items() if v is not None})
    return NormalizedEvent(**base)


@pytest.fixture
def settings() -> Settings:
    return Settings(provider="stub", audit_dir=Path(".vigil/test-audit"))


@pytest.fixture
def event() -> NormalizedEvent:
    return make_event()
