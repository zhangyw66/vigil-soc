"""Vigil command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from vigil import __version__
from vigil.config import Settings
from vigil.eval import run_eval
from vigil.ingest import load_alerts, load_normalized
from vigil.llm import get_provider
from vigil.models.triage import TriageResult
from vigil.pipeline import render_html, render_json, render_markdown, run_triage, summarize
from vigil.safety.audit import AuditLog

app = typer.Typer(
    name="vigil",
    help="Open-source AI copilot for security operations (defensive use only).",
    add_completion=False,
    no_args_is_help=True,
)


@app.command()
def ingest(
    input: Path = typer.Argument(..., help="Alert file (JSONL or CSV)."),
    format: str = typer.Option("auto", "--format", help="jsonl | csv | auto"),
    output: Path | None = typer.Option(
        None, "--out", "-o", help="Write normalized events as JSONL (default: stdout)."
    ),
) -> None:
    """Parse raw alerts into normalized events."""
    fmt = "jsonl" if format == "auto" else format
    events = load_alerts(str(input), fmt=fmt)
    typer.echo(f"[vigil] normalized {len(events)} event(s) from {input}")
    payload = "\n".join(e.model_dump_json() for e in events)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")
        typer.echo(f"[vigil] wrote {output}")
    else:
        typer.echo(payload)


@app.command()
def triage(
    input: Path = typer.Argument(..., help="Normalized events JSONL (from `vigil ingest`)."),
    provider: str | None = typer.Option(None, "--provider", help="stub | anthropic | ollama"),
    model: str | None = typer.Option(None, "--model", help="Override model name."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Deterministic scoring only."),
    output: Path | None = typer.Option(None, "--out", "-o", help="Write results JSON."),
    skip_audit: bool = typer.Option(False, "--no-audit", help="Disable the audit log."),
) -> None:
    """Run hybrid triage over normalized events."""
    settings = Settings()
    if provider:
        settings = Settings(provider=provider, claude_model=model or settings.claude_model)
    elif model:
        settings = Settings(claude_model=model)
    provider_obj = get_provider(settings.provider, settings)
    events = load_normalized(str(input))
    audit = None if skip_audit else AuditLog(settings.audit_path)
    results: list[TriageResult] = []
    for event in events:
        result = run_triage(event, provider_obj, settings, audit=audit, use_llm=not no_llm)
        results.append(result)
        typer.echo(
            f"{result.event_id}: {result.verdict:<10} final={result.final_score:5.1f} "
            f"det={result.deterministic_score:5.1f} "
            f"llm={'–' if result.llm_score is None else f'{result.llm_score:5.1f}'}"
            f"{'  ⚠ escalation' if result.escalation else ''}"
        )
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_json(results), encoding="utf-8")
        typer.echo(f"[vigil] wrote {output}")


@app.command()
def report(
    input: Path = typer.Argument(..., help="Results JSON (from `vigil triage --out`)."),
    format: str = typer.Option("md", "--format", "-f", help="md | json | html"),
    output: Path | None = typer.Option(None, "--out", "-o", help="Output file."),
) -> None:
    """Render a triage report."""
    raw = json.loads(input.read_text(encoding="utf-8"))
    results_raw = raw.get("results", raw if isinstance(raw, list) else [])
    results = [TriageResult.model_validate(r) for r in results_raw]
    summary = summarize(results)
    if format == "json":
        text = render_json(results)
    elif format == "html":
        text = render_html(results, summary)
    else:
        text = render_markdown(results, summary)
    if output:
        output.write_text(text, encoding="utf-8")
        typer.echo(f"[vigil] wrote {output}")
    else:
        typer.echo(text)


@app.command()
def eval(
    dataset: Path = typer.Argument(..., help="Labeled dataset JSONL (event + gold)."),
    provider: str | None = typer.Option(None, "--provider", help="stub | anthropic | ollama"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Benchmark deterministic-only mode."),
) -> None:
    """Run the eval harness and print classification metrics."""
    settings = Settings(provider=provider or "stub")
    report = run_eval(
        str(dataset),
        settings,
        provider_name=provider,
        use_llm=not no_llm,
    )
    typer.echo(json.dumps(report, ensure_ascii=False, indent=2))


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(f"vigil {__version__}")


if __name__ == "__main__":
    app()
