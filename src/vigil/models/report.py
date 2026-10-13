"""Report-level aggregates."""

from __future__ import annotations

from pydantic import BaseModel


class ReportSummary(BaseModel):
    total: int = 0
    benign: int = 0
    suspicious: int = 0
    malicious: int = 0
    escalated: int = 0
    avg_confidence: float = 0.0
    total_cost_usd: float = 0.0
