"""Eval metrics tests."""

from __future__ import annotations

from vigil.eval.metrics import evaluate
from vigil.models.triage import TriageResult


def _result(event_id: str, verdict: str) -> TriageResult:
    return TriageResult(
        event_id=event_id, verdict=verdict,  # type: ignore[arg-type]
        confidence=0.8, deterministic_score=50, final_score=50,
    )


def test_perfect_predictions():
    results = [_result("a", "MALICIOUS"), _result("b", "BENIGN"), _result("c", "BENIGN")]
    gold = {"a": "MALICIOUS", "b": "BENIGN", "c": "BENIGN"}
    report = evaluate(results, gold)
    assert report.accuracy == 1.0
    assert report.macro_f1 == 1.0


def test_all_wrong():
    results = [_result("a", "BENIGN"), _result("b", "MALICIOUS")]
    gold = {"a": "MALICIOUS", "b": "BENIGN"}
    report = evaluate(results, gold)
    assert report.accuracy == 0.0
    assert report.macro_f1 == 0.0


def test_escalation_rate_counted():
    results = [
        _result("a", "SUSPICIOUS"),
        TriageResult(
            event_id="b", verdict="SUSPICIOUS", confidence=0.5,
            deterministic_score=80, llm_score=40, final_score=56, escalation=True,
        ),
    ]
    gold = {"a": "SUSPICIOUS", "b": "SUSPICIOUS"}
    report = evaluate(results, gold)
    assert report.escalation_rate == 0.5
