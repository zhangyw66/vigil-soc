"""CSV connector (header row = field names)."""

from __future__ import annotations

import csv
from pathlib import Path

from vigil.ingest.base import Connector
from vigil.ingest.jsonl import JsonlConnector


class CsvConnector(Connector):
    name = "csv"

    def load(self, source: Path) -> tuple[list, list[str]]:
        if not source.exists():
            from vigil.ingest.base import IngestError

            raise IngestError(f"file not found: {source}")
        events: list = []
        errors: list[str] = []
        with source.open(encoding="utf-8", newline="") as handle:
            for lineno, row in enumerate(csv.DictReader(handle), start=2):
                try:
                    events.append(JsonlConnector._to_event(dict(row)))
                except (ValueError, KeyError) as exc:
                    errors.append(f"{source.name}:{lineno}: {exc}")
        return events, errors
