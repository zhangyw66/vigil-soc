"""Evaluation: metrics, datasets, harness."""

from vigil.eval.dataset import EvalCase, load_dataset
from vigil.eval.metrics import ClassificationReport, evaluate
from vigil.eval.run import run_eval

__all__ = ["ClassificationReport", "EvalCase", "evaluate", "load_dataset", "run_eval"]
