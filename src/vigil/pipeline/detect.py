"""Detection-rule drafting (Sigma/YARA) for confirmed-malicious events."""

from __future__ import annotations

import re

from vigil.config import Settings
from vigil.llm.prompts import SYSTEM_DETECT, build_detect_user
from vigil.llm.providers import LLMProvider
from vigil.models.event import NormalizedEvent
from vigil.models.triage import TriageResult
from vigil.pipeline.redact import redact_event
from vigil.safety.guard import frame_event

_REQUIRED_SIGMA_KEYS = ("title", "logsource", "detection")


class DetectionDraftError(ValueError):
    """Draft failed structural validation."""


def draft_sigma(
    result: TriageResult,
    event: NormalizedEvent,
    provider: LLMProvider,
    settings: Settings,
) -> str:
    """Draft a Sigma rule. Only meaningful for MALICIOUS/SUSPICIOUS events."""
    if result.verdict == "BENIGN":
        raise DetectionDraftError("refusing to draft a detection for a BENIGN event")
    payload = redact_event(event) if settings.redact else event
    response = provider.complete(SYSTEM_DETECT, build_detect_user(frame_event(payload)))
    rule = response.text.strip()
    valid, problems = validate_sigma(rule)
    if not valid:
        raise DetectionDraftError("; ".join(problems))
    return rule


def validate_sigma(rule_text: str) -> tuple[bool, list[str]]:
    """Minimal structural validation (full PySigma validation is optional)."""
    problems = [
        key
        for key in _REQUIRED_SIGMA_KEYS
        if not re.search(rf"^\s*{re.escape(key)}\s*:", rule_text, re.MULTILINE)
    ]
    return (not problems, [f"missing sigma key: {k}" for k in problems])
