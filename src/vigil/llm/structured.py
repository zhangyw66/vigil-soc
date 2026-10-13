"""Structured-output parsing with schema enforcement and bounded retries."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from vigil.llm.providers import LLMProvider, LLMResult
from vigil.safety.guard import SchemaViolation, enforce_triage_schema

_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Pull the first JSON object out of an LLM response (tolerates fences/prose)."""
    if not text:
        return None
    match = _JSON_BLOCK.search(text)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def parse_triage_response(text: str) -> dict[str, Any]:
    """Parse + schema-enforce an LLM triage response."""
    data = extract_json_object(text)
    if data is None:
        raise SchemaViolation("no JSON object found in model response")
    return enforce_triage_schema(data)


def complete_triage(
    provider: LLMProvider,
    system: str,
    user: str,
    attempts: int = 2,
) -> tuple[dict[str, Any], int, LLMResult]:
    """Call the provider and return (validated dict, attempts_used, raw response).

    Invalid or schema-violating output triggers a bounded retry with a
    correction hint; failures are raised, never silently coerced.
    """
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        response = provider.complete(system, user)
        try:
            return parse_triage_response(response.text), attempt, response
        except SchemaViolation as exc:
            last_error = exc
            user = (
                f"{user}\n\nCorrection: your previous reply was rejected "
                f"({exc}). Respond with ONLY the JSON object, exactly per schema."
            )
    raise SchemaViolation(f"LLM triage output invalid after {attempts} attempts: {last_error}")


# Registry kept small and explicit: add per-task validators here as needed.
_VALIDATORS: dict[str, Callable[[str], dict[str, Any]]] = {
    "triage": parse_triage_response,
}
