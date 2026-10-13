"""MCP Server (L3 milestone — interface sketch, not yet wired).

Planned surface for Claude Desktop / Claude Code integration:

- ``triage_alert(event_json)``  → TriageResult
- ``draft_sigma(event_id)``    → Sigma YAML
- ``search_iocs(event_id)``    → extracted IOCs
- ``run_playbook(name)``       → multi-stage IR workflow

Implementation lands in M3 of the roadmap (see VIGIL-DESIGN.md §2 L3).
"""

from __future__ import annotations

from vigil.config import Settings
from vigil.llm import get_provider
from vigil.pipeline.triage import run_triage


def triage_alert(event_json: str, settings: Settings | None = None) -> dict:
    """Programmatic entry used by MCP tooling (defensive analysis only)."""

    from vigil.models.event import NormalizedEvent

    settings = settings or Settings()
    provider = get_provider(settings.provider, settings)
    event = NormalizedEvent.model_validate_json(event_json)
    return run_triage(event, provider, settings).model_dump(mode="json")
