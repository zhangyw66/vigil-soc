"""Eval harness: run triage over a labeled dataset and report metrics."""

from __future__ import annotations

import time

from vigil.config import Settings
from vigil.eval.dataset import load_dataset
from vigil.eval.metrics import evaluate
from vigil.llm import get_provider
from vigil.models.triage import TriageResult
from vigil.pipeline.triage import run_triage


def run_eval(
    dataset_path: str,
    settings: Settings,
    *,
    provider_name: str | None = None,
    use_llm: bool = True,
) -> dict:
    provider = get_provider(provider_name or settings.provider, settings)
    cases = load_dataset(dataset_path)
    results: list[TriageResult] = []
    started = time.monotonic()
    for case in cases:
        results.append(
            run_triage(
                case.event,
                provider,
                settings,
                use_llm=use_llm,
            )
        )
    report = evaluate(results, {c.event.event_id: c.gold for c in cases})
    return {
        "dataset": dataset_path,
        "provider": getattr(provider, "model", "unknown"),
        "use_llm": use_llm,
        "elapsed_sec": round(time.monotonic() - started, 2),
        "metrics": report.to_dict(),
    }
