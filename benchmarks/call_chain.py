"""Call-chain reachability helper for the benchmark scorer.

Two tools may detect the same bug but attribute it to different functions
on the same internal-call chain (e.g. Slither reports at `_internalDeposit`
while w3goaudit reports at the unauthenticated `depositFrom` entrypoint, or
vice-versa). Strict (case_id, category, contract, function) set equality
under-credits those cases as FP+FN even though the bug WAS found.

This module loads a per-case w3goaudit database (built once with
`w3goaudit build`), extracts the contract's internal-call graph, and exposes
`is_same_chain()` so the scorer can treat two findings in the same contract
as the same bug when one is reachable from the other along internal/self
edges. The fallback when the graph is unavailable is strict equality.
"""

from __future__ import annotations

import json
import subprocess
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable


# ---- graph construction -----------------------------------------------------


def build_call_graph(db_json: dict[str, Any]) -> dict[str, dict[str, set[str]]]:
    """Build per-contract internal-call graphs from a w3goaudit DB JSON.

    Returns: { contract_name: { caller_fn: set(callee_fn) } }.

    Only internal/self/super edges are kept — those are the ones that mean
    "still inside the same logical bug". External calls are excluded so
    cross-contract attribution disagreements don't get falsely unified.
    """
    graph: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    contracts = db_json.get("contracts") or {}
    for _cid, contract in contracts.items():
        cname = contract.get("name") or ""
        if not cname:
            continue
        for fn in contract.get("functions") or []:
            caller = _bare_name(fn.get("name"))
            if not caller:
                continue
            for call in fn.get("calls") or []:
                ct = call.get("callType", "")
                if ct not in ("internal", "self", "super", "inherited"):
                    continue
                callee = _bare_name(call.get("resolvedFunction") or call.get("target"))
                if callee:
                    graph[cname][caller].add(callee)
    return graph


def _bare_name(name: str | None) -> str:
    """Strip parameter list from a function reference. The runner's
    clean_function() does the same — keep them aligned so reachability
    comparisons match the (case, category, contract, function) keys built
    elsewhere in the scorer."""
    if not name:
        return ""
    return str(name).split("(", 1)[0].strip()


def reachable(graph: dict[str, dict[str, set[str]]], contract: str, src: str, dst: str, max_depth: int = 24) -> bool:
    """BFS over internal/self edges in `contract` from `src`. True if `dst`
    is reachable (or src == dst). `max_depth` bounds pathological cycles."""
    if not contract or not src or not dst:
        return False
    if src == dst:
        return True
    edges = graph.get(contract, {})
    if not edges:
        return False
    seen = {src}
    queue: deque[tuple[str, int]] = deque([(src, 0)])
    while queue:
        cur, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for nxt in edges.get(cur, ()):
            if nxt in seen:
                continue
            if nxt == dst:
                return True
            seen.add(nxt)
            queue.append((nxt, depth + 1))
    return False


def is_same_chain(graph: dict[str, dict[str, set[str]]], contract: str, fn_a: str, fn_b: str) -> bool:
    """Direction-agnostic chain check: True if either function is reachable
    from the other along internal/self edges in `contract`."""
    if fn_a == fn_b:
        return True
    return reachable(graph, contract, fn_a, fn_b) or reachable(graph, contract, fn_b, fn_a)


# ---- per-case database loader ----------------------------------------------


def _targets_for(case: dict[str, Any]) -> list[str]:
    t = case.get("targets")
    if isinstance(t, list) and t:
        return [str(x) for x in t]
    if case.get("target"):
        return [str(case["target"])]
    return []


def build_case_database(
    case: dict[str, Any],
    repo_root: Path,
    w3goaudit_bin: Path,
    out_dir: Path,
) -> Path | None:
    """Run `w3goaudit build` on the case's target(s) and return the path to
    the resulting DB JSON. Returns None if the binary is missing or the
    build fails; callers should fall back to strict scoring in that case."""
    if not w3goaudit_bin.exists():
        return None
    targets = _targets_for(case)
    if not targets:
        return None

    out_dir.mkdir(parents=True, exist_ok=True)
    db_path = out_dir / f"{case['id']}.callgraph.json"

    # `w3goaudit build` accepts a single path, so for multi-target cases we
    # build the first one. (The chains for the others can be filled in later
    # if a real case needs it — none of today's corpora hit this path.)
    cmd = [
        str(w3goaudit_bin),
        "build",
        str(repo_root / targets[0]),
        "-o",
        str(db_path),
    ]
    try:
        subprocess.run(cmd, cwd=str(repo_root), check=True, capture_output=True, timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None
    return db_path if db_path.exists() else None


def load_case_chain_db(db_path: Path | None) -> dict[str, dict[str, set[str]]] | None:
    """Load and parse a DB JSON produced by build_case_database()."""
    if db_path is None or not db_path.exists():
        return None
    try:
        data = json.loads(db_path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    return build_call_graph(data)


# ---- scoring relaxation -----------------------------------------------------


# A scoring key is (case_id, category, contract, function). Match relaxation
# operates on the (contract, function) tail while keeping case_id and category
# strict — those identify what bug class we're scoring.


def match_relaxed(
    actual_keys: Iterable[tuple[str, str, str, str]],
    expected_keys: Iterable[tuple[str, str, str, str]],
    chains_by_case: dict[str, dict[str, dict[str, set[str]]]],
) -> tuple[list[tuple[str, str, str, str]], list[tuple[str, str, str, str]], list[tuple[str, str, str, str]]]:
    """Compute (tp, fp, fn) with call-chain reachability relaxation.

    A reported `actual` key is paired with an `expected` key when they share
    case_id + category + contract AND their functions are on the same
    internal-call chain (either direction). Strict equality remains the
    primary check, so today's exact-match scores are preserved unchanged.

    Returns sorted tuple lists.
    """
    actual_set = set(actual_keys)
    expected_set = set(expected_keys)

    # Pass 1: exact matches first (most precise).
    matched_actual = actual_set & expected_set
    matched_expected = set(matched_actual)

    actual_groups: dict[tuple[str, str, str], list[tuple[str, str, str, str]]] = defaultdict(list)
    expected_groups: dict[tuple[str, str, str], list[tuple[str, str, str, str]]] = defaultdict(list)
    for key in sorted(actual_set - matched_actual):
        actual_groups[key[:3]].append(key)
    for key in sorted(expected_set - matched_expected):
        expected_groups[key[:3]].append(key)

    # Pass 2: deterministic maximum-cardinality matching within each strict
    # case/category/contract group.
    for group in sorted(actual_groups.keys() & expected_groups.keys()):
        case_id, _category, contract = group
        graph = chains_by_case.get(case_id) or {}
        adjacency = {
            actual: [
                expected
                for expected in expected_groups[group]
                if is_same_chain(graph, contract, actual[3], expected[3])
            ]
            for actual in actual_groups[group]
        }
        expected_to_actual: dict[
            tuple[str, str, str, str], tuple[str, str, str, str]
        ] = {}

        def augment(
            actual: tuple[str, str, str, str],
            seen: set[tuple[str, str, str, str]],
        ) -> bool:
            for expected in adjacency[actual]:
                if expected in seen:
                    continue
                seen.add(expected)
                current = expected_to_actual.get(expected)
                if current is None or augment(current, seen):
                    expected_to_actual[expected] = actual
                    return True
            return False

        for actual in actual_groups[group]:
            augment(actual, set())
        matched_expected.update(expected_to_actual)
        matched_actual.update(expected_to_actual.values())

    tp = sorted(matched_expected)
    fp = sorted(actual_set - matched_actual)
    fn = sorted(expected_set - matched_expected)
    return tp, fp, fn
