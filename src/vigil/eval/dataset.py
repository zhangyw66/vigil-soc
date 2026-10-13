"""Benchmark dataset loading.

Dataset format (JSONL): one object per line with ``event`` (raw alert dict)
and ``gold`` (verdict label).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from vigil.ingest.jsonl import JsonlConnector
from vigil.models.event import NormalizedEvent


class DatasetError(ValueError):
    pass


@dataclass
class EvalCase:
    event: NormalizedEvent
    gold: str


def load_dataset(path: str) -> list[EvalCase]:
    data_path = Path(path)
    if not data_path.exists():
        raise DatasetError(f"dataset not found: {path}")
    cases: list[EvalCase] = []
    for lineno, line in enumerate(data_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DatasetError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
        event = JsonlConnector._to_event(obj.get("event", {}))
        gold = obj.get("gold")
        if gold not in {"BENIGN", "SUSPICIOUS", "MALICIOUS"}:
            raise DatasetError(f"{path}:{lineno}: gold must be a valid verdict, got {gold!r}")
        cases.append(EvalCase(event=event, gold=gold))
    return cases
