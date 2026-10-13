"""Safety layer: prompt-injection defense, provenance, audit."""

from vigil.safety.audit import AuditLog, digest
from vigil.safety.guard import (
    SchemaViolation,
    check_claims_grounded,
    enforce_triage_schema,
    frame_event,
)
from vigil.safety.provenance import grounded_in_event, tag_source_ref

__all__ = [
    "AuditLog",
    "SchemaViolation",
    "check_claims_grounded",
    "digest",
    "enforce_triage_schema",
    "frame_event",
    "grounded_in_event",
    "tag_source_ref",
]
