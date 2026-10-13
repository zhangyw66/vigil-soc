"""JSONL connector for generic alert feeds.

Expected shape (one JSON object per line):

    {"timestamp": "2026-10-01T08:12:00Z", "source": "edr", "event_type": "process_start",
     "severity": "high", "host": "web-01", "user": "svc_web",
     "process": "powershell.exe", "cmdline": "powershell -enc ...",
     "src_ip": "10.0.0.5", "dst_ip": "198.51.100.7", ...}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vigil.ingest.base import parse_ts
from vigil.models.event import NormalizedEvent


class JsonlConnector:
    name = "jsonl"

    def load(self, source: Path) -> tuple[list[NormalizedEvent], list[str]]:
        events: list[NormalizedEvent] = []
        errors: list[str] = []
        if not source.exists():
            from vigil.ingest.base import IngestError

            raise IngestError(f"file not found: {source}")
        for lineno, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(self._to_event(json.loads(line)))
            except (ValueError, KeyError) as exc:  # noqa: PERF203
                errors.append(f"{source.name}:{lineno}: {exc}")
        return events, errors

    @staticmethod
    def _to_event(data: dict[str, Any]) -> NormalizedEvent:
        ts = data.get("timestamp") or data.get("ts") or data.get("time")
        if ts is None:
            raise ValueError("missing timestamp")
        event_id = (
            data.get("event_id") or data.get("id") or data.get("uuid")
            or f"evt-{hash(json.dumps(data, sort_keys=True)) & 0xFFFFFF:06x}"
        )
        return NormalizedEvent(
            event_id=str(event_id),
            timestamp=parse_ts(ts),
            source=str(data.get("source", "unknown")),
            event_type=str(data.get("event_type", "unknown")),
            severity=data.get("severity", "info"),
            host=data.get("host"),
            user=data.get("user"),
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            dst_port=data.get("dst_port"),
            process=data.get("process"),
            cmdline=data.get("cmdline"),
            file_path=data.get("file_path"),
            file_hash=data.get("file_hash"),
            raw=data,
        )
