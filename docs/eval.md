# Evaluation

Vigil is eval-first: triage quality is measured, not assumed.

## Datasets

| Set | Size | Labeling | Status |
|---|---|---|---|
| v0 | 8 events | single-label, synthetic | shipped in `tests/fixtures/alerts/gold_v0.jsonl` |
| v1 | 200 events | 3 annotators + adjudication | planned (M3) |

All samples are synthetic/anonymized; no real customer data.

## Metrics

`vigil eval` reports: accuracy, per-class precision/recall/F1, macro F1,
escalation rate, elapsed time. Example run (offline stub provider):

```bash
vigil eval tests/fixtures/alerts/gold_v0.jsonl --provider stub
```

```
"metrics": {
  "accuracy": 1.0,
  "macro_f1": 1.0,
  "per_class": {...},
  "escalation_rate": 0.125,
  "n": 8
}
```

## Baselines

Three modes are benchmarkable:

1. **Deterministic only** (`--no-llm`) — explainable, offline, zero cost.
2. **LLM only** — best raw reasoning, no rule anchor.
3. **Hybrid** (default) — fused with escalation on disagreement.

The v1 benchmark report (vs. human-analyst consensus) is published in this doc
once the dataset lands (M3).
