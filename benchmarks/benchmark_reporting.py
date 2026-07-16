from __future__ import annotations

from pathlib import Path
from typing import Any

from benchmark_core import rel_path


def md_escape(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def percent(value: Any) -> str:
    try:
        return f"{float(value):.2%}"
    except Exception:
        return "-"


def finding_label(item: dict[str, Any]) -> str:
    function = item.get("function") or "<unknown>"
    return f"`{item.get('case_id', '')}` `{item.get('category', '')}` `{item.get('contract', '')}.{function}()`"


def short_status(status: str) -> str:
    if status == "ok":
        return "ran"
    if status == "partial_error":
        return "ran with errors"
    if status == "error":
        return "failed"
    return status or "unknown"


def write_markdown(report: dict[str, Any], path: Path) -> None:
    lines: list[str] = []
    expected_total = sum(
        len(case.get("expected", []))
        for case in report["corpus"].get("cases", [])
    )
    category_total = len(report["corpus"].get("categories", {}))
    lines.append("# Benchmark Results")
    lines.append("")
    lines.append(f"- Generated: `{report['generated_at']}`")
    lines.append(f"- Corpus: `{report['corpus']['name']}`")
    if report["corpus"].get("path"):
        lines.append(f"- Corpus file: `{report['corpus']['path']}`")
    lines.append(f"- Cases: `{len(report['corpus']['cases'])}`")
    lines.append(f"- Expected bugs: `{expected_total}`")
    lines.append(f"- Bug categories: `{category_total}`")
    lines.append(f"- Output folder: `{rel_path(path.parent)}`")
    lines.append("")
    lines.append("## What This Benchmark Does")
    lines.append("")
    lines.append(
        "It runs each tool on Solidity files with known bugs, compares tool findings with the corpus answer key, then reports:"
    )
    lines.append("")
    lines.append("| Result | Meaning |")
    lines.append("|---|---|")
    lines.append("| Found Bugs | Expected bugs the tool found. This is TP. |")
    lines.append("| Extra Noise | Findings not listed in the answer key. This is FP. |")
    lines.append("| Missed Bugs | Expected bugs the tool did not find. This is FN. |")
    lines.append("| Precision | Cleanliness. Higher means fewer extra findings. |")
    lines.append("| Detection Rate | Coverage. Higher means fewer missed bugs. |")
    lines.append("| F1 | One combined score for precision and detection rate. |")
    lines.append("")
    lines.append("## Plain English Result")
    lines.append("")
    for tool, info in report["tools"].items():
        metrics = report["metrics"].get(tool, {})
        status = short_status(metrics.get("status", info.get("status", "")))
        line = (
            f"- `{tool}` {status}: found `{metrics.get('tp', 0)}/{expected_total}` expected bugs, "
            f"missed `{metrics.get('fn', 0)}`, and produced `{metrics.get('fp', 0)}` extra findings. "
            f"Precision `{percent(metrics.get('precision', 0))}`, detection rate `{percent(metrics.get('detection_rate', 0))}`, "
            f"F1 `{percent(metrics.get('f1', 0))}`."
        )
        if metrics.get("status") == "partial_error":
            line += " Some cases failed for this tool, so compare it carefully."
        lines.append(line)
    lines.append("")
    lines.append("## Scoreboard")
    lines.append("")
    lines.append(
        "| Tool | Status | Found Bugs | Extra Noise | Missed Bugs | Precision | Detection Rate | F1 |"
    )
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|")
    for tool, info in report["tools"].items():
        metrics = report["metrics"].get(tool, {})
        lines.append(
            "| {tool} | {status} | {tp} | {fp} | {fn} | {precision} | {detection_rate} | {f1} |".format(
                tool=tool,
                status=short_status(metrics.get("status", info["status"])),
                tp=metrics.get("tp", 0),
                fp=metrics.get("fp", 0),
                fn=metrics.get("fn", 0),
                precision=percent(metrics.get("precision", 0)),
                detection_rate=percent(metrics.get("detection_rate", 0)),
                f1=percent(metrics.get("f1", 0)),
            )
        )
    lines.append("")
    lines.append("## By Bug Type")
    lines.append("")
    lines.append(
        "| Tool | Bug Type | Found | Noise | Missed | Precision | Detection Rate | F1 |"
    )
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|")
    for tool, metrics in report["metrics"].items():
        for category, block in metrics.get("by_category", {}).items():
            lines.append(
                f"| {tool} | {category} | {block['tp']} | {block['fp']} | {block['fn']} | {percent(block['precision'])} | {percent(block['detection_rate'])} | {percent(block['f1'])} |"
            )
    lines.append("")
    lines.append("## Missed Bugs")
    lines.append("")
    for tool, metrics in report["metrics"].items():
        false_negatives = metrics.get("false_negatives", [])
        if not false_negatives:
            lines.append(f"- `{tool}` missed no expected bugs.")
            continue
        lines.append(f"- `{tool}` missed `{len(false_negatives)}` expected bugs:")
        for item in false_negatives[:15]:
            lines.append(f"  - {finding_label(item)}")
        if len(false_negatives) > 15:
            lines.append(f"  - ... {len(false_negatives) - 15} more")
    lines.append("")
    lines.append("## Extra Findings")
    lines.append("")
    lines.append(
        "These are benchmark-category findings that were not in the corpus answer key. They are noise for scoring, but some may still be real bugs if the answer key is incomplete."
    )
    lines.append("")
    for tool, metrics in report["metrics"].items():
        false_positives = metrics.get("false_positives", [])
        if not false_positives:
            lines.append(f"- `{tool}` produced no extra findings.")
            continue
        lines.append(f"- `{tool}` produced `{len(false_positives)}` extra findings:")
        for item in false_positives[:15]:
            lines.append(f"  - {finding_label(item)}")
        if len(false_positives) > 15:
            lines.append(f"  - ... {len(false_positives) - 15} more")
    lines.append("")
    lines.append("## Files Created")
    lines.append("")
    lines.append("| Path | What It Contains |")
    lines.append("|---|---|")
    lines.append(f"| `{rel_path(path)}` | This human-readable report. |")
    lines.append(
        f"| `{rel_path(path.with_name('benchmark.json'))}` | The same result as JSON for scripts or dashboards. |"
    )
    lines.append(
        f"| `{rel_path(path.parent / 'raw')}/` | Raw output from each tool and case, useful when debugging a failed run. |"
    )
    lines.append("")
    lines.append("## Run Details")
    lines.append("")
    lines.append("Use this section when a tool failed or returned strange results.")
    lines.append("")
    lines.append(
        "| Tool | Case | Status | Exit | Runtime ms | Raw | Scoped | Error |"
    )
    lines.append("|---|---|---:|---:|---:|---:|---:|---|")
    for run in report["runs"]:
        lines.append(
            f"| {run['tool']} | {run['case_id']} | {short_status(run['status'])} | {run.get('exit_code')} | {run.get('duration_ms')} | {run.get('raw_findings')} | {run.get('scoped_findings')} | {md_escape(run.get('error', ''))} |"
        )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
