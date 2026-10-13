"""Redaction tests: PII must never reach the LLM."""

from __future__ import annotations

from tests.conftest import make_event
from vigil.pipeline.redact import redact_event, redact_text


def test_email_redacted():
    red = redact_text("contact admin@example.com please")
    assert "admin@example.com" not in red.text
    assert "email" in red.mapping


def test_anthropic_key_redacted():
    red = redact_text("key=sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890")
    assert "sk-ant-" not in red.text
    assert "anthropic_key" in red.mapping


def test_generic_secret_redacted():
    red = redact_text("password=Sup3rS3cretValue")
    assert "Sup3rS3cretValue" not in red.text


def test_cn_id_and_phone_redacted():
    red = redact_text("id=110101199001011234 phone=13800138000")
    assert "110101199001011234" not in red.text
    assert "13800138000" not in red.text


def test_redact_event_preserves_structure_and_records_mapping():
    event = make_event(cmdline="powershell -enc abcd user=admin@example.com")
    redacted = redact_event(event)
    assert redacted.cmdline is not None
    assert "admin@example.com" not in redacted.cmdline
    assert "_redactions" in redacted.raw
    assert "cmdline" in redacted.raw["_redactions"]
