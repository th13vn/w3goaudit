#!/usr/bin/env python3
"""Fail CI when W3GoAudit's competitive benchmark drops below its quality bar."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any


COUNT_KEYS = ("tp", "fp", "fn", "failed_cases")
METRIC_KEYS = ("precision", "detection_rate", "f1")


def _count(metrics: dict[str, Any], key: str) -> int:
    value = metrics.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{key} must be a non-negative integer")
    return value


def _finite_metric(metrics: dict[str, Any], key: str) -> float:
    value = metrics.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{key} must be a finite number")
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(f"{key} must be a finite number between 0 and 1")
    return number


def _raw_metric_block(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    detection_rate = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * detection_rate / (precision + detection_rate)
        if precision + detection_rate
        else 0.0
    )
    return {
        "precision": precision,
        "detection_rate": detection_rate,
        "f1": f1,
    }


def validate_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    """Require complete, finite metrics and verify ratios against raw counts."""
    if not isinstance(metrics, dict):
        raise ValueError("tool metrics must be an object")

    counts = {key: _count(metrics, key) for key in COUNT_KEYS}
    reported = {key: _finite_metric(metrics, key) for key in METRIC_KEYS}
    raw = _raw_metric_block(counts["tp"], counts["fp"], counts["fn"])
    expected = {key: round(value, 4) for key, value in raw.items()}
    for key in METRIC_KEYS:
        if not math.isclose(reported[key], expected[key], rel_tol=0.0, abs_tol=1e-12):
            raise ValueError(
                f"{key}={reported[key]} is inconsistent with tp/fp/fn "
                f"(expected {expected[key]})"
            )

    return {
        **counts,
        **expected,
        "_raw_precision": raw["precision"],
        "_raw_detection_rate": raw["detection_rate"],
    }


def validate_threshold(value: float, name: str) -> float:
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be a finite number between 0 and 1")
    return value


def meets_thresholds(
    metrics: dict[str, Any], min_precision: float, min_recall: float
) -> bool:
    try:
        validated = validate_metrics(metrics)
        min_precision = validate_threshold(min_precision, "min_precision")
        min_recall = validate_threshold(min_recall, "min_recall")
    except ValueError:
        return False
    return (
        validated["failed_cases"] == 0
        and validated["_raw_precision"] >= min_precision
        and validated["_raw_detection_rate"] >= min_recall
    )


def summary(metrics: dict[str, Any]) -> dict[str, Any]:
    keys = ("tp", "fp", "fn", "precision", "detection_rate", "f1", "failed_cases")
    return {key: metrics[key] for key in keys}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--tool", default="w3goaudit")
    parser.add_argument("--min-precision", type=float, default=0.65)
    parser.add_argument("--min-recall", type=float, default=0.95)
    args = parser.parse_args(argv)

    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        metrics = validate_metrics(report["metrics"][args.tool])
        validate_threshold(args.min_precision, "min_precision")
        validate_threshold(args.min_recall, "min_recall")
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"cannot read benchmark metrics for {args.tool}: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(summary(metrics), indent=2))
    return 0 if meets_thresholds(metrics, args.min_precision, args.min_recall) else 1


if __name__ == "__main__":
    raise SystemExit(main())
