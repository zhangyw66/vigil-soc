"""Optional LLM enrichment: context, ATT&CK mapping, next steps."""

from __future__ import annotations

from vigil.config import Settings
from vigil.llm.prompts import SYSTEM_ENRICH, build_enrich_user
from vigil.llm.providers import LLMProvider
from vigil.llm.structured import extract_json_object
from vigil.models.event import NormalizedEvent
from vigil.pipeline.redact import redact_event
from vigil.safety.guard import frame_event


def enrich_event(
    event: NormalizedEvent,
    provider: LLMProvider,
    settings: Settings,
) -> dict:
    """Return enrichment JSON (never trusted: schema-check before use)."""
    payload = redact_event(event) if settings.redact else event
    response = provider.complete(SYSTEM_ENRICH, build_enrich_user(frame_event(payload)))
    data = extract_json_object(response.text) or {}
    return data
