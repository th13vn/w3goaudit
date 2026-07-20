from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import call_chain
from benchmark_core import clean_function


def expected_keys(corpus: dict[str, Any]) -> set[tuple[str, str, str, str]]:
    # Expected labels are the answer key. A finding is correct only when it has
    # the same case, bug category, contract, and function as one of these rows.
    keys: set[tuple[str, str, str, str]] = set()
    for case in corpus.get("cases", []):
        for item in case.get("expected", []):
            keys.add(
                (
                    case["id"],
                    item["category"],
                    item["contract"],
                    clean_function(item.get("function", "")),
                )
            )
    return keys


def finding_key(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        finding.get("case_id", ""),
        finding.get("category", ""),
        finding.get("contract", ""),
        clean_function(finding.get("function", "")),
    )


def evaluate_tool(
    tool: str,
    runs: list[dict[str, Any]],
    corpus: dict[str, Any],
    chains_by_case: dict[str, dict[str, dict[str, set[str]]]] | None = None,
) -> dict[str, Any]:
    # Convert each tool's raw alerts into one shared shape, then compare against
    # the corpus answer key:
    #   TP = expected and found
    #   FP = found but not expected
    #   FN = expected but not found
    #
    # When chains_by_case is provided (built once per benchmark run from a
    # `w3goaudit build` of each case's target), the comparison is relaxed: a
    # reported finding on the same contract is credited as a TP for an
    # expected entry when their functions are on the same internal-call chain.
    chains_by_case = chains_by_case or {}
    expected = expected_keys(corpus)
    actual_map: dict[
        tuple[str, str, str, str], list[dict[str, Any]]
    ] = defaultdict(list)
    raw_findings = 0
    scoped_occurrences = 0
    duration_ms = 0.0
    errors = 0
    for run in runs:
        raw_findings += run.get("raw_findings", 0)
        scoped_occurrences += run.get("scoped_findings", 0)
        duration_ms += float(run.get("duration_ms") or 0)
        if run.get("status") != "ok":
            errors += 1
        for finding in run.get("findings", []):
            if finding.get("category"):
                actual_map[finding_key(finding)].append(finding)
    actual = set(actual_map)
    if chains_by_case:
        tp, fp, fn = call_chain.match_relaxed(actual, expected, chains_by_case)
    else:
        tp = sorted(expected & actual)
        fp = sorted(actual - expected)
        fn = sorted(expected - actual)
    metrics = metric_block(len(tp), len(fp), len(fn))
    by_category = {}
    categories = sorted(corpus.get("categories", {}).keys())
    tp_set = set(tp)
    fp_set = set(fp)
    fn_set = set(fn)
    for category in categories:
        tp_c = {key for key in tp_set if key[1] == category}
        fp_c = {key for key in fp_set if key[1] == category}
        fn_c = {key for key in fn_set if key[1] == category}
        by_category[category] = metric_block(len(tp_c), len(fp_c), len(fn_c))
    return {
        "tool": tool,
        "status": "ok" if errors == 0 else "partial_error",
        "cases": len(runs),
        "failed_cases": errors,
        "duration_ms": round(duration_ms, 2),
        "raw_findings": raw_findings,
        "scoped_occurrences": scoped_occurrences,
        "unique_scoped_findings": len(actual),
        **metrics,
        "by_category": by_category,
        "true_positives": [key_to_dict(x) for x in tp],
        "false_positives": [key_to_dict(x) for x in fp],
        "false_negatives": [key_to_dict(x) for x in fn],
    }


def metric_block(tp: int, fp: int, fn: int) -> dict[str, Any]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    detection_rate = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * detection_rate / (precision + detection_rate)
        if precision + detection_rate
        else 0.0
    )
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "detection_rate": round(detection_rate, 4),
        "f1": round(f1, 4),
    }


def key_to_dict(key: tuple[str, str, str, str]) -> dict[str, str]:
    return {
        "case_id": key[0],
        "category": key[1],
        "contract": key[2],
        "function": key[3],
    }


def build_chain_graphs(
    cases: list[dict[str, Any]],
    root: Path,
    w3goaudit_bin: Path | None,
    out_dir: Path,
) -> dict[str, dict[str, dict[str, set[str]]]]:
    if w3goaudit_bin is None:
        return {}
    graphs: dict[str, dict[str, dict[str, set[str]]]] = {}
    for case in cases:
        db_path = call_chain.build_case_database(
            case, root, w3goaudit_bin, out_dir
        )
        graph = call_chain.load_case_chain_db(db_path)
        if graph is not None:
            graphs[case["id"]] = graph
    return graphs
