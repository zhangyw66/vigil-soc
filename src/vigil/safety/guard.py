"""Prompt-injection defenses.

Security telemetry is untrusted: an attacker-controlled log field can embed
instructions aimed at the LLM. Vigil's pipeline therefore enforces:

1. **Data/instruction plane separation** — event data travels inside explicit
   `<event_data>` framing and is never spliced into instruction templates.
2. **Instruction hierarchy** — system instructions outrank user context, which
   outranks untrusted data; declared in ``llm/prompts.py``.
3. **Strict output schema** — LLM JSON is validated against the triage schema;
   invalid output is rejected (never silently coerced).
4. **Provenance** — LLM claims must reference event fields (see ``provenance.py``).
"""

from __future__ import annotations

import json
from typing import Any

from vigil.models.event import NormalizedEvent
from vigil.models.triage import TriageResult, Verdict

DATA_TAG_OPEN = "<event_data>"
DATA_TAG_CLOSE = "</event_data>"

_VALID_VERDICTS: tuple[Verdict, ...] = ("BENIGN", "SUSPICIOUS", "MALICIOUS")


class SchemaViolation(ValueError):
    """LLM output did not conform to the required schema."""


def frame_event(event: NormalizedEvent) -> str:
    """Serialize an event as *data* for the model.

    The framing tags are also declared in the system prompt, so the model
    knows anything inside them is data — never instructions.
    """
    payload = json.dumps(
        event.model_dump(mode="json"), ensure_ascii=False, sort_keys=True
    )
    return f"{DATA_TAG_OPEN}\n{payload}\n{DATA_TAG_CLOSE}"


def enforce_triage_schema(data: dict[str, Any]) -> dict[str, Any]:
    """Validate an LLM-produced triage object. Raises SchemaViolation on any issue."""
    verdict = data.get("verdict")
    if verdict not in _VALID_VERDICTS:
        raise SchemaViolation(f"verdict must be one of {_VALID_VERDICTS}, got {verdict!r}")
    confidence_raw = data.get("confidence")
    if confidence_raw is None:
        raise SchemaViolation("confidence is required")
    confidence: Any
    try:
        confidence = float(confidence_raw)
    except (TypeError, ValueError) as exc:
        raise SchemaViolation(f"confidence must be numeric, got {confidence_raw!r}") from exc
    if not 0.0 <= confidence <= 1.0:
        raise SchemaViolation(f"confidence out of range: {confidence}")
    llm_score = data.get("llm_score")
    if llm_score is not None:
        try:
            llm_score = float(llm_score)
        except (TypeError, ValueError) as exc:
            raise SchemaViolation(f"llm_score must be numeric, got {llm_score!r}") from exc
        if not 0.0 <= llm_score <= 100.0:
            raise SchemaViolation(f"llm_score out of range: {llm_score}")
    if not isinstance(data.get("reasons", []), list):
        raise SchemaViolation("reasons must be a list")
    return {
        "verdict": verdict,
        "confidence": confidence,
        "llm_score": llm_score,
        "reasons": data.get("reasons", []),
        "mitre_attack": data.get("mitre_attack", []),
        "iocs": data.get("iocs", []),
    }


def check_claims_grounded(result: TriageResult, event: NormalizedEvent) -> list[str]:
    """Surface ungrounded LLM claims as warnings (do not silently drop them)."""
    from vigil.safety.provenance import ground_llm_reasons

    return ground_llm_reasons(result.reasons, event)
