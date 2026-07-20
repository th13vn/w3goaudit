#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from benchmark_adapters import ADAPTERS, ToolAdapter  # noqa: E402
from benchmark_core import (  # noqa: E402
    AliasMatcher,
    CaseSourceIndex,
    ROOT,
    TOOL_EXECUTABLES,
    case_targets,
    find_executable,
    load_tool_manifests,
    prepare_requested_tool,
    rel_path,
    repo_path,
    require_tools,
    resolve_output_path,
)
from benchmark_reporting import write_markdown  # noqa: E402
from benchmark_scoring import build_chain_graphs, evaluate_tool  # noqa: E402

# Friendly suite names for normal use. A user should not need to remember long
# JSON paths for the common benchmark modes.
SUITES = {
    # Default: cross-tool union corpus — every vulnerability at least one of the
    # compared tools (slither / semgrep-decurity / 4naly3er) can find.
    "competitive": "scripts/benchmark/corpus/competitive.json",
    # Per-tool parity suites scoped to a single tool's detector set.
    "slither": "scripts/benchmark/corpus/slither-inspired.json",
    "decurity": "scripts/benchmark/corpus/decurity-semgrep-inspired.json",
    "4naly3er": "scripts/benchmark/corpus/4naly3er-inspired.json",
}

CONTAINER_RESULTS_ROOT = Path("/workspace/benchmarks/results")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the W3GoAudit benchmark. Default: the competitive suite "
            "(cross-tool union corpus), output to benchmarks/results/latest."
        )
    )
    parser.add_argument("--root", default=str(ROOT), help="repository root")
    parser.add_argument(
        "--suite",
        default="competitive",
        choices=sorted(SUITES),
        help="benchmark set to run: competitive (default, cross-tool union), slither, decurity, or 4naly3er",
    )
    parser.add_argument(
        "--corpus",
        default="",
        help="advanced: path to a custom corpus JSON; overrides --suite",
    )
    parser.add_argument("--out", default="benchmarks/results/latest", help="output folder")
    parser.add_argument(
        "--tools",
        default="w3goaudit,slither,semgrep,4naly3er",
        help="comma-separated tool list (w3goaudit, slither, semgrep, 4naly3er, aderyn)",
    )
    parser.add_argument("--timeout", type=int, default=180, help="per-tool per-case timeout in seconds")
    parser.add_argument("--w3goaudit-bin", default="", help="use an existing w3goaudit binary")
    parser.add_argument(
        "--config-dir",
        default="scripts/benchmark/config",
        help="directory holding per-tool detector manifests (config/<tool>/detectors.json)",
    )
    parser.add_argument(
        "--semgrep-config",
        default="scripts/benchmark/config/semgrep-decurity",
        help="Semgrep config dir/file or registry ruleset (default: vendored Decurity rules)",
    )
    parser.add_argument(
        "--naly3er-cmd",
        default="",
        help="command used to invoke 4naly3er (default: '4naly3er' on PATH, or $W3_NALY3ER_CMD)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    selected = [name.strip() for name in args.tools.split(",") if name.strip()]
    unknown = [name for name in selected if name not in ADAPTERS]
    if unknown:
        raise SystemExit(f"unknown tools: {', '.join(unknown)}")
    overrides: dict[str, str] = {}
    if args.w3goaudit_bin:
        overrides["w3goaudit"] = args.w3goaudit_bin
    naly3er_cmd = args.naly3er_cmd or os.environ.get("W3_NALY3ER_CMD", "")
    if naly3er_cmd:
        overrides["4naly3er"] = naly3er_cmd
    args.resolved_tools = require_tools(selected, overrides)

    out_dir = repo_path(args.out, root)
    if os.environ.get("W3GOAUDIT_BENCHMARK_CONTAINER") == "1":
        out_dir = resolve_output_path(CONTAINER_RESULTS_ROOT, out_dir)

    corpus_path = args.corpus or SUITES[args.suite]
    corpus = json.loads(repo_path(corpus_path, root).read_text(encoding="utf-8"))
    # Auto-load per-tool detector manifests so a tool's native check IDs map onto
    # shared categories even when the corpus omits an explicit alias for them.
    manifest_aliases = load_tool_manifests(args.config_dir, selected, root)
    matcher = AliasMatcher(corpus, manifest_aliases)

    tools: dict[str, dict[str, Any]] = {}
    adapters: list[tuple[str, ToolAdapter]] = []
    for name in selected:
        adapter = ADAPTERS[name](root, out_dir, matcher, args)
        tools[name] = prepare_requested_tool(name, adapter)
        adapters.append((name, adapter))

    raw_dir = out_dir / "raw"
    # Raw files are per-run evidence. Clear old raw logs before a new run.
    if raw_dir.exists():
        shutil.rmtree(raw_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)

    source_indexes = {
        case["id"]: CaseSourceIndex(case_targets(case), root)
        for case in corpus.get("cases", [])
    }

    runs: list[dict[str, Any]] = []
    metrics: dict[str, dict[str, Any]] = {}

    # Build one shared mapping before scanners run so attribution is identical
    # regardless of which comparison tools were selected. If no helper is
    # available, scoring keeps its strict-equality fallback.
    chain_binary_text = args.resolved_tools.get("w3goaudit") or find_executable(
        TOOL_EXECUTABLES["w3goaudit"]
    )
    chain_binary = Path(chain_binary_text) if chain_binary_text else None
    chains_by_case = build_chain_graphs(
        corpus.get("cases", []),
        root,
        chain_binary,
        raw_dir / ".callgraphs",
    )

    for name, adapter in adapters:
        tool_runs = []
        for case in corpus.get("cases", []):
            run = adapter.run_case(case, source_indexes[case["id"]])
            runs.append(run)
            tool_runs.append(run)
        metrics[name] = evaluate_tool(name, tool_runs, corpus, chains_by_case)

    report = {
        "schema_version": "1.0",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "root": str(root),
        "corpus": {
            "name": corpus.get("name", ""),
            "description": corpus.get("description", ""),
            "path": rel_path(corpus_path, root),
            "cases": corpus.get("cases", []),
            "categories": corpus.get("categories", {}),
        },
        "tools": tools,
        "metrics": metrics,
        "runs": runs,
    }

    (out_dir / "benchmark.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, out_dir / "benchmark.md")
    print(f"Wrote {rel_path(out_dir / 'benchmark.md', root)}")
    print(f"Wrote {rel_path(out_dir / 'benchmark.json', root)}")
    for tool, block in metrics.items():
        print(
            f"{tool}: precision={block['precision']:.2%} detection_rate={block['detection_rate']:.2%} "
            f"f1={block['f1']:.2%} raw={block['raw_findings']} scoped={block['unique_scoped_findings']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
