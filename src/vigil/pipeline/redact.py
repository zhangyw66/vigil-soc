"""PII redaction applied *before* any LLM call.

Redaction is reversible via the per-event mapping stored in
``raw["_redactions"]`` — reports can restore real values locally, while the
LLM never sees them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from vigil.models.event import NormalizedEvent

_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "anthropic_key": re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"),
    "generic_secret": re.compile(r"(?i)\b(api[_-]?key|token|secret|password)\b\s*[=:]\s*[^\s,;]{12,}"),
    "cn_id": re.compile(r"\b\d{17}[\dXx]\b"),
    "cn_phone": re.compile(r"\b(?:\+?86[- ]?)?1[3-9]\d{9}\b"),
}


@dataclass
class Redaction:
    text: str
    mapping: dict[str, list[str]] = field(default_factory=dict)


def redact_text(text: str) -> Redaction:
    result = text
    mapping: dict[str, list[str]] = {}
    for name, pattern in _PATTERNS.items():
        placeholders: list[str] = []

        def _replace(match: re.Match[str], _name: str = name, _ph: list[str] = placeholders) -> str:
            _ph.append(f"{{{{{_name}_{len(_ph)}}}}}")
            return _ph[-1]

        result = pattern.sub(_replace, result)
        if placeholders:
            mapping[name] = placeholders
    return Redaction(text=result, mapping=mapping)


def redact_event(event: NormalizedEvent) -> NormalizedEvent:
    """Return a copy of the event with PII redacted from free-text fields."""
    data = event.model_dump()
    for field_name in ("cmdline", "file_path", "user"):
        value = data.get(field_name)
        if isinstance(value, str) and value:
            red = redact_text(value)
            data[field_name] = red.text
            data["raw"].setdefault("_redactions", {})[field_name] = red.mapping
    return NormalizedEvent.model_validate(data)
