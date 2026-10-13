#!/usr/bin/env bash
# Benchmark script: run the offline eval harness end to end.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== ingest =="
python -m vigil.cli ingest tests/fixtures/alerts/sample_alerts.jsonl --out /tmp/vigil_norm.jsonl

echo "== triage (stub, offline) =="
python -m vigil.cli triage /tmp/vigil_norm.jsonl --provider stub --out /tmp/vigil_results.json

echo "== report =="
python -m vigil.cli report /tmp/vigil_results.json --format md --out /tmp/vigil_report.md
head -20 /tmp/vigil_report.md

echo "== eval (gold v0) =="
python -m vigil.cli eval tests/fixtures/alerts/gold_v0.jsonl --provider stub
