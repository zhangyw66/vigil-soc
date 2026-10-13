"""Report rendering: Markdown / JSON / HTML."""

from __future__ import annotations

import json
from datetime import datetime

from vigil.models.report import ReportSummary
from vigil.models.triage import TriageResult


def summarize(results: list[TriageResult]) -> ReportSummary:
    total = len(results)
    counts = {v: 0 for v in ("BENIGN", "SUSPICIOUS", "MALICIOUS")}
    for r in results:
        counts[r.verdict] += 1
    return ReportSummary(
        total=total,
        benign=counts["BENIGN"],
        suspicious=counts["SUSPICIOUS"],
        malicious=counts["MALICIOUS"],
        escalated=sum(1 for r in results if r.escalation),
        avg_confidence=round(sum(r.confidence for r in results) / total, 2) if total else 0.0,
        total_cost_usd=round(sum(r.cost_usd for r in results), 6),
    )


def render_json(results: list[TriageResult]) -> str:
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": summarize(results).model_dump(),
        "results": [r.model_dump(mode="json") for r in results],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_markdown(results: list[TriageResult], summary: ReportSummary) -> str:
    lines = [
        "# Vigil Triage Report",
        "",
        f"- Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"- Total: {summary.total} · BENIGN {summary.benign} · SUSPICIOUS {summary.suspicious} · "
        f"MALICIOUS {summary.malicious} · Escalated {summary.escalated}",
        f"- Avg confidence: {summary.avg_confidence} · Est. cost: ${summary.total_cost_usd:.6f}",
        "",
        "| event_id | verdict | conf | det | llm | final | esc | key evidence |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        evidence = "; ".join(
            f"{item.claim} ({item.source_ref})" for item in r.reasons[:3]
        )
        lines.append(
            f"| {r.event_id} | {r.verdict} | {r.confidence:.2f} | {r.deterministic_score:.0f} | "
            f"{r.llm_score if r.llm_score is None else f'{r.llm_score:.0f}'} | {r.final_score:.0f} | "
            f"{'⚠' if r.escalation else ''} | {evidence} |"
        )
    return "\n".join(lines)


def render_html(results: list[TriageResult], summary: ReportSummary) -> str:
    rows = "".join(
        f"<tr><td>{r.event_id}</td><td><span class='v-{r.verdict.lower()}'>{r.verdict}</span></td>"
        f"<td>{r.confidence:.2f}</td><td>{r.deterministic_score:.0f}</td>"
        f"<td>{'–' if r.llm_score is None else f'{r.llm_score:.0f}'}</td><td>{r.final_score:.0f}</td>"
        f"<td>{'⚠' if r.escalation else ''}</td></tr>"
        for r in results
    )
    return f"""<!doctype html>
<html lang="zh"><head><meta charset="utf-8"><title>Vigil Triage Report</title></head>
<body style="font-family:system-ui,sans-serif;margin:24px;color:#1a1b1c">
<h2>Vigil Triage Report</h2>
<p>Total {summary.total} · BENIGN {summary.benign} · SUSPICIOUS {summary.suspicious} ·
MALICIOUS {summary.malicious} · Escalated {summary.escalated} ·
Est. cost ${summary.total_cost_usd:.6f}</p>
<table border="1" cellspacing="0" cellpadding="6" style="border-collapse:collapse">
<tr><th>event_id</th><th>verdict</th><th>conf</th><th>det</th><th>llm</th><th>final</th><th>esc</th></tr>
{rows}
</table>
<style>.v-benign{{color:#2f7d32}}.v-suspicious{{color:#b26a00}}.v-malicious{{color:#c62828}}</style>
</body></html>
"""
