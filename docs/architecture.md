# Architecture

```
Sources (EDR / IDS / SIEM / TI / vuln reports)
   │
   ▼
Ingest (JSONL · CSV · Elasticsearch · Splunk · Sentinel — plugin-based)
   │
   ▼
Normalize (OCSF-like NormalizedEvent · dedup · field mapping)
   │
   ▼
Pipeline: Redact → Enrich(LLM) → Triage(rules ⊕ LLM) → Detect(Sigma/YARA) → Report
   │
   ▼
Output: CLI · JSON/Markdown/HTML · MCP Server · Dashboard

Cross-cutting: Safety (prompt-injection defense · provenance · audit)
               Eval  (benchmarks · regression)
```

## Design principles

1. **Local-first** — SQLite/JSONL by default; data never leaves your network
   except to the LLM provider you configure.
2. **Plug-in everywhere** — connectors and LLM providers implement small
   protocols; register via entry points.
3. **Auditable by construction** — every LLM call is logged with a prompt
   digest, latency and cost; every claim carries a source reference.
4. **Hybrid, not black-box** — deterministic scoring is always computed and
   fused with the LLM; disagreement escalates to a human.

## Core modules

| Module | Responsibility |
|---|---|
| `vigil.ingest` | Connectors → `NormalizedEvent` |
| `vigil.pipeline.score` | Deterministic rules + TI reputation (no LLM) |
| `vigil.pipeline.triage` | Fusion, verdicts, escalation |
| `vigil.llm` | Providers (stub/anthropic/ollama), prompts, structured output |
| `vigil.safety` | Data-plane framing, provenance, audit, redaction |
| `vigil.eval` | Labeled datasets, metrics, harness |
