"""Elasticsearch connector (example remote plugin, L2 milestone).

Pulls recent documents from an index and normalizes common fields.
Configure via environment:

    VIGIL_ES_URL=http://localhost:9200
    VIGIL_ES_INDEX=security-events-*
    VIGIL_ES_SIZE=500
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx

from vigil.ingest.base import Connector, IngestError
from vigil.ingest.jsonl import JsonlConnector


class ElasticsearchConnector(Connector):
    name = "elasticsearch"

    def load(self, source: Path) -> tuple[list, list[str]]:
        url = os.getenv("VIGIL_ES_URL", "http://localhost:9200").rstrip("/")
        index = os.getenv("VIGIL_ES_INDEX", "security-events-*")
        size = int(os.getenv("VIGIL_ES_SIZE", "500"))
        try:
            resp = httpx.post(
                f"{url}/{index}/_search",
                json={"size": size, "query": {"match_all": {}}},
                timeout=30.0,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise IngestError(f"elasticsearch query failed: {exc}") from exc
        hits = resp.json().get("hits", {}).get("hits", [])
        events: list = []
        errors: list[str] = []
        for hit in hits:
            try:
                events.append(JsonlConnector._to_event(hit.get("_source", {})))
            except (ValueError, KeyError) as exc:
                errors.append(f"es hit {hit.get('_id')}: {exc}")
        return events, errors
