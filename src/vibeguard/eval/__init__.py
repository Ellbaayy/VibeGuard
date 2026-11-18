"""Eval harness: labelled diffs in, precision/recall out."""

from vibeguard.eval.cases import CASES, EvalCase
from vibeguard.eval.runner import CaseResult, EvalReport, format_eval_text, run_eval

__all__ = [
    "CASES",
    "CaseResult",
    "EvalCase",
    "EvalReport",
    "format_eval_text",
    "run_eval",
]
