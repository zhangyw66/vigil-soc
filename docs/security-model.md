# Security model

Security telemetry is **untrusted**. An attacker who controls a log field can
embed instructions aimed at the LLM (prompt injection). Vigil treats this as a
first-class threat and enforces four defenses:

## 1. Data / instruction plane separation

Event data travels inside `<event_data>` tags and is never spliced into
instruction templates. The system prompt declares that content inside the tags
is data, not instructions. See `vigil/safety/guard.py::frame_event`.

## 2. Instruction hierarchy

System instructions > analyst context > untrusted data. The hierarchy is
declared in `vigil/llm/prompts.py` and reinforced with schema-enforced output.

## 3. Provenance

Every LLM claim must reference a real event field (`event.<field>`) or another
checkable source. Ungrounded claims are surfaced as warnings, not silently
kept. See `vigil/safety/provenance.py`.

## 4. Strict output schema + bounded retries

LLM responses are validated against the triage schema (verdict enum,
confidence ∈ [0,1], reasons list). Invalid output is rejected and retried at
most twice; persistent failure falls back to the deterministic score and is
recorded in the audit log. See `vigil/llm/structured.py`.

## Privacy & audit

- PII redaction runs **before** any LLM call; the reversible mapping stays
  local (`vigil/pipeline/redact.py`).
- The audit log stores prompt **digests**, never raw content, plus latency and
  cost per call (`vigil/safety/audit.py`).
- **Zero telemetry**: no analytics, no callbacks. The only outbound traffic is
  the LLM provider you configure.
