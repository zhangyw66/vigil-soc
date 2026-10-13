"""Model validation tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from tests.conftest import make_event
from vigil.models.triage import TriageResult


def test_normalized_event_default_severity():
    event = make_event()
    assert event.severity == "medium"


def test_normalized_event_rejects_bad_severity():
    with pytest.raises(ValidationError):
        make_event(severity="ultra")


def test_triage_result_bounds_confidence():
    with pytest.raises(ValidationError):
        TriageResult(
            event_id="e1", verdict="MALICIOUS", confidence=1.5,
            deterministic_score=50, final_score=50,
        )


def test_triage_result_rejects_unknown_verdict():
    with pytest.raises(ValidationError):
        TriageResult(
            event_id="e1", verdict="MAYBE", confidence=0.5,
            deterministic_score=50, final_score=50,
        )
