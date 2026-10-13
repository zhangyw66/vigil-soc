"""CLI end-to-end smoke tests (stub provider, no network)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vigil.cli import app
from vigil.models.event import NormalizedEvent

runner = CliRunner()

FIXTURES = Path(__file__).parent / "fixtures" / "alerts"


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "vigil" in result.stdout


def test_ingest_jsonl(tmp_path):
    out = tmp_path / "norm.jsonl"
    result = runner.invoke(
        app, ["ingest", str(FIXTURES / "sample_alerts.jsonl"), "--out", str(out)]
    )
    assert result.exit_code == 0, result.output
    events = [
        NormalizedEvent.model_validate_json(line)
        for line in out.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(events) >= 5


def test_ingest_csv(tmp_path):
    csv_path = FIXTURES / "sample_alerts.csv"
    out = tmp_path / "norm.jsonl"
    result = runner.invoke(app, ["ingest", str(csv_path), "--format", "csv", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()


def test_triage_and_report_roundtrip(tmp_path):
    norm = tmp_path / "norm.jsonl"
    results = tmp_path / "results.json"
    md = tmp_path / "report.md"
    ingested = runner.invoke(
        app, ["ingest", str(FIXTURES / "sample_alerts.jsonl"), "--out", str(norm)]
    )
    assert ingested.exit_code == 0, ingested.output
    triage = runner.invoke(
        app, ["triage", str(norm), "--provider", "stub", "--out", str(results)]
    )
    assert triage.exit_code == 0, triage.output
    data = json.loads(results.read_text(encoding="utf-8"))
    assert data["summary"]["total"] >= 5
    report = runner.invoke(app, ["report", str(results), "--format", "md", "--out", str(md)])
    assert report.exit_code == 0
    assert "# Vigil Triage Report" in md.read_text(encoding="utf-8")


def test_eval_on_gold_dataset(tmp_path):
    result = runner.invoke(app, ["eval", str(FIXTURES / "gold_v0.jsonl"), "--provider", "stub"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["metrics"]["accuracy"] == 1.0
