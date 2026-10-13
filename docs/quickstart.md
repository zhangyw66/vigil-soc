# Quickstart

## Install

```bash
pip install vigil-soc            # offline demo works out of the box
pip install "vigil-soc[claude]"  # add Claude support
```

## 1. Ingest

```bash
vigil ingest alerts.jsonl --out normalized.jsonl
```

## 2. Triage (offline demo with the built-in stub provider)

```bash
vigil triage normalized.jsonl --provider stub --out results.json
```

## 3. Report

```bash
vigil report results.json --format md     # or html / json
```

## 4. Benchmark

```bash
vigil eval tests/fixtures/alerts/gold_v0.jsonl --provider stub
```

## Using Claude

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export VIGIL_PROVIDER=anthropic
export VIGIL_CLAUDE_MODEL=claude-sonnet-5-5
vigil triage normalized.jsonl
```

Every LLM call is schema-enforced, audit-logged, and PII-redacted before it
leaves your network. See [security-model.md](security-model.md).

## Configuration (env vars)

| Variable | Default | Meaning |
|---|---|---|
| `VIGIL_PROVIDER` | `stub` | `stub` \| `anthropic` \| `ollama` |
| `VIGIL_CLAUDE_MODEL` | `claude-sonnet-5-5` | Claude model name |
| `VIGIL_W_DET` / `VIGIL_W_LLM` | `0.4` / `0.6` | Fusion weights |
| `VIGIL_BENIGN_CUTOFF` / `VIGIL_MALICIOUS_CUTOFF` | `30` / `70` | Verdict thresholds |
| `VIGIL_ESCALATION_DELTA` | `25` | Rule/LLM disagreement → escalate |
| `VIGIL_REDACT` | `true` | PII redaction before LLM |
| `VIGIL_AUDIT_DIR` | `.vigil/audit` | Audit log location |
| `VIGIL_TI_FILE` | `.vigil/ti.json` | Threat-intel reputation file |
