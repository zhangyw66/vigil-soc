"""Hybrid triage orchestrator: deterministic score ⊕ LLM judgment."""

from __future__ import annotations

from vigil.config import Settings
from vigil.llm import complete_triage
from vigil.llm.prompts import SYSTEM_TRIAGE, build_triage_user
from vigil.llm.providers import LLMProvider
from vigil.models.event import NormalizedEvent
from vigil.models.triage import EvidenceItem, TriageResult, Verdict
from vigil.pipeline.redact import redact_event
from vigil.pipeline.score import DeterministicScorer, ThreatIntel
from vigil.safety.audit import AuditLog, digest
from vigil.safety.guard import SchemaViolation, frame_event

_FALLBACK_REASON = EvidenceItem(
    claim="LLM triage failed schema validation; decision based on deterministic score only",
    source_ref="rule",
    kind="rule_hit",
)


def run_triage(
    event: NormalizedEvent,
    provider: LLMProvider,
    settings: Settings,
    *,
    scorer: DeterministicScorer | None = None,
    audit: AuditLog | None = None,
    use_llm: bool = True,
) -> TriageResult:
    """Run the full triage pipeline for one event.

    Guarantees:
    - Deterministic score always computed (offline-safe).
    - LLM output is schema-enforced; invalid output falls back to the
      deterministic score and is recorded in the audit log.
    - Deterministic/LLM disagreement beyond ``escalation_delta`` escalates.
    """
    scorer = scorer or DeterministicScorer(ThreatIntel.from_file(settings.ti_file))
    det_score, det_reasons, iocs = scorer.score(event)

    llm_score: float | None = None
    llm_reasons: list[EvidenceItem] = []
    latency_ms = 0
    cost_usd = 0.0
    ok = True
    note = ""

    if use_llm:
        payload = redact_event(event) if settings.redact else event
        user = build_triage_user(
            frame_event(payload), det_score, [r.claim for r in det_reasons]
        )
        prompt_digest = digest(user)
        try:
            data, _, response = complete_triage(provider, SYSTEM_TRIAGE, user)
            llm_score = float(data["llm_score"] or 0.0)
            llm_reasons = [
                EvidenceItem(**r) for r in data["reasons"] if isinstance(r, dict)
            ]
            latency_ms = response.latency_ms
            cost_usd = response.cost_usd
        except SchemaViolation as exc:
            ok = False
            note = str(exc)
            llm_reasons = [_FALLBACK_REASON]
        if audit is not None:
            audit.record(
                event_id=event.event_id,
                model=getattr(provider, "model", "unknown"),
                latency_ms=latency_ms,
                cost_usd=cost_usd,
                prompt_digest=prompt_digest,
                ok=ok,
                note=note,
            )

    # --- fusion ---
    if llm_score is None:
        final_score = det_score
    else:
        final_score = settings.w_deterministic * det_score + settings.w_llm * llm_score

    if final_score < settings.benign_cutoff:
        verdict: Verdict = "BENIGN"
    elif final_score > settings.malicious_cutoff:
        verdict = "MALICIOUS"
    else:
        verdict = "SUSPICIOUS"

    escalation = llm_score is not None and abs(det_score - llm_score) > settings.escalation_delta
    confidence = round(min(0.95, 0.5 + abs(final_score - 50.0) / 100.0), 2)

    reasons = det_reasons + llm_reasons
    deduped: list[EvidenceItem] = []
    seen: set[tuple[str, str]] = set()
    for item in reasons:
        key = (item.claim, item.source_ref)
        if key not in seen:
            seen.add(key)
            deduped.append(item)

    return TriageResult(
        event_id=event.event_id,
        verdict=verdict,
        confidence=confidence,
        deterministic_score=round(det_score, 1),
        llm_score=round(llm_score, 1) if llm_score is not None else None,
        final_score=round(final_score, 1),
        reasons=deduped,
        iocs=iocs,
        escalation=escalation,
        model=getattr(provider, "model", "unknown"),
        latency_ms=latency_ms,
        cost_usd=cost_usd,
    )
