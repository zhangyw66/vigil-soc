"""Provenance helpers: anchor every claim to a checkable source."""

from __future__ import annotations

from vigil.models.event import NormalizedEvent
from vigil.models.triage import EvidenceItem


def tag_source_ref(field: str, value: object) -> str:
    """Normalize a source reference for an event field."""
    return f"event.{field}" if value is not None else f"event.{field}=<absent>"


def grounded_in_event(source_ref: str, event: NormalizedEvent) -> bool:
    """Whether a source reference points at a real event field."""
    if source_ref.startswith("ti.") or source_ref in {"llm.inference", "rule"}:
        return True
    if source_ref.startswith("event."):
        field = source_ref.split(".", 1)[1].split("=", 1)[0]
        return field in type(event).model_fields
    return False


def ground_llm_reasons(reasons: list[EvidenceItem], event: NormalizedEvent) -> list[str]:
    """Return warnings for LLM claims that reference non-existent fields."""
    warnings: list[str] = []
    for item in reasons:
        if item.kind == "llm_inference" and not grounded_in_event(item.source_ref, event):
            warnings.append(
                f"ungrounded llm claim: {item.claim!r} references {item.source_ref!r}"
            )
    return warnings
