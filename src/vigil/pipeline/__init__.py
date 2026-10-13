"""Pipeline layer."""

from vigil.pipeline.detect import DetectionDraftError, draft_sigma, validate_sigma
from vigil.pipeline.enrich import enrich_event
from vigil.pipeline.redact import redact_event, redact_text
from vigil.pipeline.report import render_html, render_json, render_markdown, summarize
from vigil.pipeline.score import DeterministicScorer, ThreatIntel, extract_iocs, is_private_ip
from vigil.pipeline.triage import run_triage

__all__ = [
    "DetectionDraftError",
    "DeterministicScorer",
    "ThreatIntel",
    "draft_sigma",
    "enrich_event",
    "extract_iocs",
    "is_private_ip",
    "redact_event",
    "redact_text",
    "render_html",
    "render_json",
    "render_markdown",
    "run_triage",
    "summarize",
    "validate_sigma",
]
