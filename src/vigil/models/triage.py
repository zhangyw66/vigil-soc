"""Triage output models: every claim carries a source reference."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["BENIGN", "SUSPICIOUS", "MALICIOUS"]


class EvidenceItem(BaseModel):
    """One piece of evidence behind a triage decision.

    ``source_ref`` anchors the claim to something checkable:
    ``event.<field>`` (a source event field), ``ti.<indicator>`` (threat
    intelligence hit), ``rule.<rule_id>`` (deterministic rule) or
    ``llm.inference`` (model reasoning, least trusted).
    """

    claim: str
    source_ref: str
    kind: Literal["event_field", "ti_lookup", "rule_hit", "llm_inference"]


class TriageResult(BaseModel):
    """Output of the hybrid (deterministic ⊕ LLM) triage pipeline."""

    event_id: str
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    deterministic_score: float = Field(ge=0.0, le=100.0)
    llm_score: float | None = Field(default=None, ge=0.0, le=100.0)
    final_score: float = Field(ge=0.0, le=100.0)
    reasons: list[EvidenceItem] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    escalation: bool = False
    model: str = "stub"
    latency_ms: int = 0
    cost_usd: float = 0.0
