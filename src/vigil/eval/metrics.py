"""Classification metrics for the eval harness.

Every number here is computed from the actual verdicts — nothing is estimated.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vigil.models.triage import TriageResult

CLASSES = ("BENIGN", "SUSPICIOUS", "MALICIOUS")


@dataclass
class ClassificationReport:
    accuracy: float = 0.0
    macro_f1: float = 0.0
    per_class: dict[str, dict[str, float]] = field(default_factory=dict)
    escalation_rate: float = 0.0
    n: int = 0

    def to_dict(self) -> dict:
        return {
            "n": self.n,
            "accuracy": round(self.accuracy, 4),
            "macro_f1": round(self.macro_f1, 4),
            "per_class": {k: {m: round(v, 4) for m, v in p.items()} for k, p in self.per_class.items()},
            "escalation_rate": round(self.escalation_rate, 4),
        }


def _f1(precision: float, recall: float) -> float:
    return 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0


def evaluate(results: list[TriageResult], gold: dict[str, str]) -> ClassificationReport:
    """Compare triage verdicts against gold labels keyed by event_id."""
    report = ClassificationReport(n=len(results))
    if not results:
        return report

    correct = 0
    per_class: dict[str, dict[str, float]] = {}
    present = set(gold.values()) & set(CLASSES)
    for cls in CLASSES:
        tp = fp = fn = 0
        for r in results:
            label = gold.get(r.event_id)
            if label is None:
                continue
            if label == cls:
                if r.verdict == cls:
                    tp += 1
                else:
                    fn += 1
            elif r.verdict == cls:
                fp += 1
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        per_class[cls] = {"precision": precision, "recall": recall, "f1": _f1(precision, recall)}

    matched = 0
    for r in results:
        if gold.get(r.event_id) is None:
            continue
        matched += 1
        if r.verdict == gold[r.event_id]:
            correct += 1

    report.accuracy = correct / matched if matched else 0.0
    report.macro_f1 = (
        sum(per_class[c]["f1"] for c in present) / len(present) if present else 0.0
    )
    report.per_class = per_class
    report.escalation_rate = sum(1 for r in results if r.escalation) / len(results)
    return report
