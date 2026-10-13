"""Hybrid triage orchestration tests."""

from __future__ import annotations

from pathlib import Path

from tests.conftest import make_event
from vigil.llm import StubProvider, get_provider
from vigil.pipeline.triage import run_triage
from vigil.safety.audit import AuditLog


def test_encoded_powershell_verdict_malicious(settings):
    event = make_event(
        cmdline="powershell.exe -nop -w hidden -enc SQBFAFgA", dst_ip="45.45.45.45"
    )
    result = run_triage(event, StubProvider(), settings)
    assert result.verdict == "MALICIOUS"
    assert result.llm_score is not None
    assert not result.escalation


def test_rule_llm_disagreement_escalates(settings):
    # deterministic sees account creation + cmd.exe (80) while the LLM scores
    # the generic event low (25) — |80-25| > 25 → escalate.
    event = make_event(
        event_type="user_added",
        process="cmd.exe",
        cmdline="net user backdoor P@ss /add",
    )
    result = run_triage(event, StubProvider(), settings)
    assert result.escalation is True
    assert result.verdict == "SUSPICIOUS"


def test_no_llm_falls_back_to_deterministic(settings):
    event = make_event(cmdline="mimikatz.exe sekurlsa::logonpasswords")
    result = run_triage(event, StubProvider(), settings, use_llm=False)
    assert result.llm_score is None
    assert result.final_score == result.deterministic_score
    assert result.verdict == "MALICIOUS"


def test_audit_log_records_calls(settings, tmp_path):
    audit = AuditLog(Path(tmp_path) / "audit.jsonl")
    event = make_event(cmdline="whoami")
    run_triage(event, StubProvider(), settings, audit=audit)
    lines = audit.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert "whoami" not in lines[0]  # raw prompts are never persisted


def test_get_provider_unknown_raises(settings):
    try:
        get_provider("does-not-exist", settings)
    except ValueError:
        return
    raise AssertionError("expected ValueError for unknown provider")
