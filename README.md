# Vigil — The Analyst Who Never Sleeps

**Vigil** is an open-source AI copilot for security operations. It helps SOC analysts triage security alerts, enrich context, and draft detection rules (Sigma / YARA) — with a research-grade, prompt-injection-resilient LLM pipeline and a built-in evaluation harness.

> ⚠️ **Intended use:** Vigil is a **defensive** tool. Use it only on systems and data you own or are explicitly authorized to analyze. It never generates offensive payloads; its outputs are triage decisions, evidence chains, and detection rules.

## Why Vigil

- **Alert triage at scale**: turn thousands of alerts into a ranked, evidence-backed queue of *benign / suspicious / malicious* decisions.
- **Deterministic ⊕ LLM hybrid scoring**: rule- and reputation-based scoring is fused with Claude's judgment; when the two disagree, the alert is escalated to a human instead of silently decided.
- **Built for untrusted data**: security telemetry can contain injected instructions. Vigil separates *data plane* from *instruction plane*, tags every LLM claim with a source reference, and enforces structured output — see [security-model.md](docs/security-model.md).
- **Eval-first**: ships with labeled benchmark datasets and reproducible precision/recall/calibration reports.
- **Local-first, zero telemetry**: your data stays in your network; LLM calls go only to the provider you configure.

## Quick start

```bash
pip install vigil-soc

# Ingest alerts (JSONL) and triage them with Claude
vigil ingest alerts.jsonl --format jsonl
vigil triage --provider anthropic --model claude-sonnet-5-5 --out report.json
vigil report --out triage_report.html

# Run the evaluation harness on the bundled benchmark
vigil eval --dataset benchmark/v1.jsonl
```

Requirements: Python 3.11+, an Anthropic API key (or any provider implementing the `LLMProvider` protocol, e.g. Ollama for offline use).

## Architecture

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

Cross-cutting: Safety (prompt-injection defense · provenance · audit) · Eval (benchmarks · regression)
```

## Roadmap

- **L1 (MVP)**: JSONL/CSV ingest, LLM enrichment, hybrid triage, reports, eval v0 (50 labeled alerts)
- **L2**: ES/Splunk/Sentinel connectors, Sigma/YARA drafting, PII redaction, prompt-injection hardening, cost tracking
- **L3**: MCP Server (Claude Desktop / Claude Code), IR playbooks, eval v1 (200-alert benchmark vs. human analysts), local-model fallback

See [docs/architecture.md](docs/architecture.md) and the public roadmap for details.

## Security & privacy

- **No telemetry.** No built-in callbacks, no analytics, no data leaving your network unless you configure a remote LLM provider.
- **PII redaction** before any LLM call; audit log records every call (input digest, output, tokens, cost, latency).
- **Responsible disclosure**: found a vulnerability in Vigil? See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome — bug reports, connectors, benchmark samples, docs. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
