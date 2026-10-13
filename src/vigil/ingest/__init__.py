"""Ingest layer: connectors turn raw telemetry into NormalizedEvents."""

from vigil.ingest.base import Connector, IngestError, parse_ts
from vigil.ingest.csv_ingest import CsvConnector
from vigil.ingest.jsonl import JsonlConnector
from vigil.ingest.plugins import discover_connectors

__all__ = [
    "Connector",
    "CsvConnector",
    "IngestError",
    "JsonlConnector",
    "discover_connectors",
    "parse_ts",
]

_REGISTRY: dict[str, type[Connector]] = {
    "jsonl": JsonlConnector,
    "csv": CsvConnector,
}


def load_alerts(path: str, fmt: str = "jsonl") -> list:
    """Load alerts from a file into a list of NormalizedEvents."""
    from pathlib import Path

    connector_type = _REGISTRY.get(fmt) or _REGISTRY.get(Path(path).suffix.lstrip(".").lower())
    if connector_type is None:
        raise IngestError(f"no connector for format {fmt!r}")
    connector = connector_type()
    events, errors = connector.load(Path(path))
    if errors:
        # Parse failures are reported but do not abort the batch.
        print(f"[vigil] ingest: {len(errors)} row(s) skipped (see logs)")
    return events


def load_normalized(path: str) -> list:
    """Load previously-normalized events (JSONL of NormalizedEvent)."""
    from pathlib import Path

    from vigil.models.event import NormalizedEvent

    events: list[NormalizedEvent] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(NormalizedEvent.model_validate_json(line))
    return events