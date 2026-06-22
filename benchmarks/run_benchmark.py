#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import time

# Local module — same-call-chain mapper that relaxes (case, category,
# contract, function) equality when two tools attribute the same bug to
# different functions on the same internal-call chain. See call_chain.py.
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
import call_chain  # noqa: E402
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

# Friendly suite names for normal use. A user should not need to remember long
# JSON paths for the common benchmark modes.
SUITES = {
    # Default: cross-tool union corpus — every vulnerability at least one of the
    # compared tools (slither / semgrep-decurity / 4naly3er) can find.
    "competitive": "benchmarks/corpus/competitive.json",
    # Per-tool parity suites scoped to a single tool's detector set.
    "slither": "benchmarks/corpus/slither-inspired.json",
    "decurity": "benchmarks/corpus/decurity-semgrep-inspired.json",
    "4naly3er": "benchmarks/corpus/4naly3er-inspired.json",
}

# Common install locations on macOS/Linux. This keeps the guide commands clean:
# users can run `python3 benchmarks/run_benchmark.py` when Go, Slither, or
# Semgrep live in a standard place.
COMMON_BIN_DIRS = [
    "/usr/local/go/bin",
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
]


def find_executable(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    for directory in COMMON_BIN_DIRS:
        candidate = Path(directory) / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return ""


def repo_path(value: str | Path, root: Path = ROOT) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def rel_path(path: str | Path, root: Path = ROOT) -> str:
    if not path:
        return ""
    p = Path(path)
    try:
        if not p.is_absolute():
            p = root / p
        return p.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def case_targets(case: dict[str, Any]) -> list[str]:
    # A case usually has one Solidity file (`target`). Some cases use `targets`
    # to merge multiple files into one logical benchmark category.
    targets = case.get("targets")
    if isinstance(targets, list) and targets:
        return [str(target) for target in targets]
    return [str(case["target"])]


def expanded_solc_targets(case: dict[str, Any], root: Path) -> list[str]:
    """Variant of case_targets() for adapters that compile each Solidity file
    independently (Slither/Semgrep): when the corpus target is a directory,
    return every .sol file inside it as a separate target.

    Why: tools that drive solc (Slither via crytic-compile) abort the whole
    batch on a single fragment's compile failure. Splitting the directory
    into per-file targets means one broken fragment doesn't bury the other
    20–60 fragments' findings. The runner's raw_stem() already supports a
    multi-target case (produces case_id__<slugified-path> raw files), so
    expanding here flows through end to end.
    """
    out: list[str] = []
    for target in case_targets(case):
        path = repo_path(target, root)
        if path.is_dir():
            out.extend(rel_path(p, root) for p in sorted(path.rglob("*.sol")) if p.is_file())
        else:
            out.append(target)
    return out


def safe_path_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")
    return slug or "target"


def clean_function(name: str | None) -> str:
    if not name:
        return ""
    return str(name).split("(", 1)[0].strip()


def norm_rule(rule: str | None) -> str:
    return (rule or "").strip().lower()


def strip_comments(line: str) -> str:
    return line.split("//", 1)[0]


class SourceIndex:
    """Tiny Solidity source index used to map line numbers back to names.

    Some tools only report "line 123". The benchmark needs "Contract.function"
    to compare that alert with the expected labels, so this helper scans the
    source text and builds rough contract/function ranges.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lines = path.read_text(encoding="utf-8").splitlines()
        self.contracts = self._build_ranges(r"\b(contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)")
        self.functions = self._build_function_ranges()

    def lookup(self, line: int | None) -> tuple[str, str]:
        if not line:
            return "", ""
        contract = ""
        function = ""
        for start, end, name in self.contracts:
            if start <= line <= end:
                contract = name
                break
        for start, end, name in self.functions:
            if start <= line <= end:
                function = name
                break
        return contract, function

    def _build_ranges(self, pattern: str) -> list[tuple[int, int, str]]:
        out: list[tuple[int, int, str]] = []
        rx = re.compile(pattern)
        for idx, raw in enumerate(self.lines):
            match = rx.search(strip_comments(raw))
            if match:
                name = match.group(2)
                out.append((idx + 1, self._block_end(idx), name))
        return out

    def _build_function_ranges(self) -> list[tuple[int, int, str]]:
        out: list[tuple[int, int, str]] = []
        function_rx = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)")
        special_rx = re.compile(r"^\s*(receive|fallback)\s*\(")
        for idx, raw in enumerate(self.lines):
            text = strip_comments(raw)
            match = function_rx.search(text)
            name = ""
            if match:
                name = match.group(1)
            else:
                special = special_rx.search(text)
                if special:
                    name = special.group(1)
            if name:
                out.append((idx + 1, self._block_end(idx), name))
        return out

    def _block_end(self, start_idx: int) -> int:
        depth = 0
        seen_open = False
        for idx in range(start_idx, len(self.lines)):
            text = strip_comments(self.lines[idx])
            for char in text:
                if char == "{":
                    depth += 1
                    seen_open = True
                elif char == "}" and seen_open:
                    depth -= 1
            if seen_open and depth <= 0:
                return idx + 1
            if not seen_open and ";" in text:
                return idx + 1
        return len(self.lines)


class CaseSourceIndex:
    """Source lookup for a benchmark case.

    A case may contain one target file or many target files. This wrapper picks
    the right SourceIndex based on the file path reported by a tool.
    """

    def __init__(self, targets: list[str], root: Path) -> None:
        self.root = root
        self.default: SourceIndex | None = None
        self.by_path: dict[str, SourceIndex] = {}
        # Expand any directory target into the .sol files inside it. This lets
        # a corpus case point a single `target` at a per-detector subdirectory
        # (e.g. test-data/slither-detectors/) instead of enumerating
        # every fragment in a verbose `targets:` array.
        files: list[Path] = []
        for target in targets:
            path = repo_path(target, root)
            if path.is_dir():
                files.extend(sorted(p for p in path.rglob("*.sol") if p.is_file()))
            else:
                files.append(path)
        for path in files:
            index = SourceIndex(path)
            if self.default is None:
                self.default = index
            self.by_path[rel_path(path, root)] = index
            try:
                self.by_path[str(path.resolve())] = index
            except Exception:
                pass

    def lookup(self, line: int | None, file_path: str | None = None) -> tuple[str, str]:
        if not line:
            return "", ""
        index = self._index_for(file_path)
        return index.lookup(line) if index else ("", "")

    def _index_for(self, file_path: str | None) -> SourceIndex | None:
        if file_path:
            rel = rel_path(file_path, self.root)
            if rel in self.by_path:
                return self.by_path[rel]
            try:
                abs_path = str(repo_path(file_path, self.root).resolve())
                if abs_path in self.by_path:
                    return self.by_path[abs_path]
            except Exception:
                pass
        return self.default


class AliasMatcher:
    """Maps each tool's rule names onto our shared benchmark categories.

    Example: W3GoAudit may report SEC-GEN-REENTRANCY while Slither reports
    reentrancy-eth. The corpus says both aliases mean category "reentrancy".
    """

    def __init__(self, corpus: dict[str, Any], manifest_aliases: dict[str, list[tuple[str, str]]] | None = None) -> None:
        self.by_tool: dict[str, dict[str, str]] = defaultdict(dict)
        # Per-tool detector manifests (config/<tool>/detectors.json) are loaded
        # FIRST so the corpus's own `aliases` block can override a manifest entry
        # when a corpus deliberately narrows a category. The manifest is the
        # broad safety net: it maps every detector a tool can emit onto its
        # shared category, so a finding the tool genuinely produced is never
        # left uncategorized (and therefore never silently dropped from TP).
        valid_categories = set(corpus.get("categories", {}).keys())
        for tool, pairs in (manifest_aliases or {}).items():
            for value, category in pairs:
                if category in valid_categories:
                    self.by_tool[tool][norm_rule(value)] = category
        for category, meta in corpus.get("categories", {}).items():
            aliases = meta.get("aliases", {})
            for tool, values in aliases.items():
                for value in values:
                    self.by_tool[tool][norm_rule(value)] = category

    def category_for(self, tool: str, rule_id: str | None) -> str:
        rule = norm_rule(rule_id)
        if not rule:
            return ""
        aliases = self.by_tool.get(tool, {})
        if rule in aliases:
            return aliases[rule]
        for alias, category in aliases.items():
            if alias and alias in rule:
                return category
        return ""


def run_command(
    cmd: list[str],
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout: int,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=merged_env,
        )
        stdout_path.write_text(proc.stdout or "", encoding="utf-8")
        stderr_path.write_text(proc.stderr or "", encoding="utf-8")
        return {
            "exit_code": proc.returncode,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        stdout_path.write_text(exc.stdout or "", encoding="utf-8")
        stderr_path.write_text((exc.stderr or "") + "\nTIMEOUT\n", encoding="utf-8")
        return {
            "exit_code": None,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "timed_out": True,
        }


def aggregate_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    if not results:
        return {"exit_code": 0, "duration_ms": 0, "timed_out": False}
    exit_code = 0
    for result in results:
        code = result.get("exit_code")
        if code not in (0, None):
            exit_code = code
            break
    if exit_code == 0 and any(result.get("exit_code") is None for result in results):
        exit_code = None
    return {
        "exit_code": exit_code,
        "duration_ms": round(sum(float(result.get("duration_ms") or 0) for result in results), 2),
        "timed_out": any(result.get("timed_out") for result in results),
    }


def combine_raw_files(dest: Path, parts: list[tuple[str, Path]]) -> Path:
    if len(parts) == 1:
        return parts[0][1]
    chunks: list[str] = []
    for target, path in parts:
        chunks.append(f"===== {target} :: {path.name} =====\n")
        try:
            chunks.append(path.read_text(encoding="utf-8"))
        except Exception as exc:
            chunks.append(f"<could not read {path}: {exc}>\n")
        if chunks and not chunks[-1].endswith("\n"):
            chunks.append("\n")
    dest.write_text("\n".join(chunks), encoding="utf-8")
    return dest


def version_from(cmd: list[str], cwd: Path, timeout: int = 30) -> str:
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        return f"unknown ({exc})"
    text = (proc.stdout or proc.stderr or "").strip().splitlines()
    return text[0] if text else "unknown"


def load_tool_manifests(
    config_dir: str | Path, tools: list[str], root: Path
) -> dict[str, list[tuple[str, str]]]:
    """Load per-tool detector manifests from `<config_dir>/<tool>/detectors.json`.

    Slither and 4naly3er have built-in detectors (no rule files), so their
    `detectors.json` manifest is the canonical map from a native detector
    id/code onto a shared benchmark category. Returns
    `{tool: [(match_string, category), ...]}`; the AliasMatcher folds these in
    as aliases. Tools without a manifest (e.g. semgrep, which runs real rule
    files) simply contribute nothing here and rely on the corpus `aliases`.

    Each manifest entry may carry an `aliases` list of extra native strings
    (the real code, title fragments) that also map to the same category — this
    is what makes output conversion robust across the slightly different forms
    a tool prints (`H-1`, `tx-origin`, "Use of tx.origin", ...).
    """
    base = repo_path(config_dir, root)
    out: dict[str, list[tuple[str, str]]] = {}
    for tool in tools:
        manifest = base / tool / "detectors.json"
        if not manifest.exists():
            continue
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except Exception:
            continue
        pairs: list[tuple[str, str]] = []
        for det in data.get("detectors", []):
            category = det.get("category")
            if not category:
                continue
            for value in [det.get("id")] + list(det.get("aliases", [])):
                if value:
                    pairs.append((str(value), category))
        if pairs:
            out[tool] = pairs
    return out


class ToolAdapter:
    """Base class for tool adapters.

    Each adapter runs one scanner and converts its native output into the same
    finding format. This keeps scoring simple and fair.
    """

    name = "base"

    def __init__(self, root: Path, out_dir: Path, matcher: AliasMatcher, args: argparse.Namespace) -> None:
        self.root = root
        self.out_dir = out_dir
        self.raw_dir = out_dir / "raw"
        self.matcher = matcher
        self.args = args

    def available(self) -> tuple[bool, str]:
        return False, "not implemented"

    def prepare(self) -> None:
        return None

    def version(self) -> str:
        return "unknown"

    def run_case(self, case: dict[str, Any], source: CaseSourceIndex) -> dict[str, Any]:
        raise NotImplementedError

    def raw_stem(self, case: dict[str, Any], target: str) -> str:
        targets = case_targets(case)
        if len(targets) == 1:
            return case["id"]
        return f"{case['id']}__{safe_path_slug(target)}"

    def finding(
        self,
        case: dict[str, Any],
        rule_id: str,
        file_path: str,
        contract: str = "",
        function: str = "",
        line: int | None = None,
        severity: str = "",
        message: str = "",
    ) -> dict[str, Any]:
        category = self.matcher.category_for(self.name, rule_id)
        return {
            "tool": self.name,
            "case_id": case["id"],
            "category": category,
            "rule_id": rule_id,
            "file": rel_path(file_path, self.root),
            "contract": contract,
            "function": clean_function(function),
            "line": line or 0,
            "severity": severity,
            "message": (message or "").strip().splitlines()[0:1][0] if message else "",
        }


class W3GoAuditAdapter(ToolAdapter):
    name = "w3goaudit"

    def __init__(self, root: Path, out_dir: Path, matcher: AliasMatcher, args: argparse.Namespace) -> None:
        super().__init__(root, out_dir, matcher, args)
        # The benchmark builds the local tool for repeatable runs. Keep that
        # binary out of the visible result folder so users only see reports and
        # raw scanner output.
        self.binary = Path(args.w3goaudit_bin) if args.w3goaudit_bin else self.raw_dir / ".bin" / "w3goaudit"

    def available(self) -> tuple[bool, str]:
        if self.binary.exists():
            return True, ""
        if not find_executable("go"):
            return False, "go is not installed and --w3goaudit-bin was not provided"
        return True, ""

    def prepare(self) -> None:
        if self.args.w3goaudit_bin and self.binary.exists():
            return
        self.binary.parent.mkdir(parents=True, exist_ok=True)
        stdout = self.raw_dir / "w3goaudit-build.stdout"
        stderr = self.raw_dir / "w3goaudit-build.stderr"
        result = run_command(
            [find_executable("go") or "go", "build", "-o", str(self.binary), "./cmd/w3goaudit"],
            self.root,
            stdout,
            stderr,
            self.args.timeout,
        )
        if result["exit_code"] != 0 or not self.binary.exists():
            raise RuntimeError(f"failed to build w3goaudit, see {stderr}")

    def version(self) -> str:
        return version_from([str(self.binary), "version"], self.root)

    def run_case(self, case: dict[str, Any], source: CaseSourceIndex) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        stdout_parts: list[tuple[str, Path]] = []
        stderr_parts: list[tuple[str, Path]] = []
        status = "ok"
        errors: list[str] = []
        last_cmd: list[str] = []
        for target in case_targets(case):
            stem = self.raw_stem(case, target)
            # w3goaudit (>=0.3) writes a result FOLDER, not a single JSON file.
            # The machine-readable findings land at <out>/corpus/findings.json.
            outdir = self.raw_dir / f"{stem}.w3goaudit.out"
            stdout = self.raw_dir / f"{stem}.w3goaudit.stdout"
            stderr = self.raw_dir / f"{stem}.w3goaudit.stderr"
            stdout_parts.append((target, stdout))
            stderr_parts.append((target, stderr))
            cmd = [
                str(self.binary),
                target,
                "-t",
                case["templates"],
                "-o",
                str(outdir),
                "--ignore-invalid-templates",
            ]
            last_cmd = cmd
            result = run_command(cmd, self.root, stdout, stderr, self.args.timeout)
            results.append(result)
            findings_path = outdir / "corpus" / "findings.json"
            if findings_path.exists():
                try:
                    data = json.loads(findings_path.read_text(encoding="utf-8"))
                    for item in data.get("findings", []):
                        loc = item.get("location", {})
                        findings.append(
                            self.finding(
                                case,
                                item.get("template_id", ""),
                                loc.get("file", target),
                                loc.get("contract", ""),
                                loc.get("function", ""),
                                loc.get("line", 0),
                                item.get("severity", ""),
                                item.get("title", ""),
                            )
                        )
                except Exception as exc:
                    status = "error"
                    errors.append(f"could not parse {findings_path}: {exc}")
            else:
                status = "error"
                errors.append(f"expected output was not written: {findings_path}")
        stdout = combine_raw_files(self.raw_dir / f"{case['id']}.w3goaudit.stdout", stdout_parts)
        stderr = combine_raw_files(self.raw_dir / f"{case['id']}.w3goaudit.stderr", stderr_parts)
        return make_run(self.name, case, last_cmd, aggregate_results(results), stdout, stderr, findings, status, "; ".join(errors))


class SlitherAdapter(ToolAdapter):
    name = "slither"

    def __init__(self, root: Path, out_dir: Path, matcher: AliasMatcher, args: argparse.Namespace) -> None:
        super().__init__(root, out_dir, matcher, args)
        self.binary = find_executable("slither")

    def available(self) -> tuple[bool, str]:
        return (True, "") if self.binary else (False, "slither is not installed")

    def version(self) -> str:
        return version_from([self.binary, "--version"], self.root)

    def run_case(self, case: dict[str, Any], source: CaseSourceIndex) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        stdout_parts: list[tuple[str, Path]] = []
        stderr_parts: list[tuple[str, Path]] = []
        status = "ok"
        errors: list[str] = []
        skipped: list[str] = []
        produced = 0
        last_cmd: list[str] = []
        # Expand directory targets into per-file targets so one fragment's
        # solc compile failure doesn't poison the whole batch (see the
        # expanded_solc_targets docstring).
        expanded = expanded_solc_targets(case, self.root)
        multi = len(expanded) > 1
        for target in expanded:
            # Inline stem (rather than self.raw_stem) so multi-target naming
            # works off the expanded list, not the corpus's `target` count.
            stem = case["id"] if not multi else f"{case['id']}__{safe_path_slug(target)}"
            output = self.raw_dir / f"{stem}.slither.json"
            stdout = self.raw_dir / f"{stem}.slither.stdout"
            stderr = self.raw_dir / f"{stem}.slither.stderr"
            stdout_parts.append((target, stdout))
            stderr_parts.append((target, stderr))
            cmd = [self.binary, target, "--json", str(output)]
            last_cmd = cmd
            result = run_command(cmd, self.root, stdout, stderr, self.args.timeout)
            results.append(result)
            if output.exists():
                produced += 1
                try:
                    data = json.loads(output.read_text(encoding="utf-8"))
                    for item in data.get("results", {}).get("detectors", []):
                        contract, function, line, file_path = slither_location(item)
                        if not contract and line:
                            contract, function = source.lookup(line, file_path or target)
                        findings.append(
                            self.finding(
                                case,
                                item.get("check", ""),
                                file_path or target,
                                contract,
                                function,
                                line,
                                item.get("impact", ""),
                                item.get("description", ""),
                            )
                        )
                except Exception as exc:
                    status = "error"
                    errors.append(f"could not parse {output}: {exc}")
            else:
                # No JSON for this fragment. For a compiler-based tool this is
                # almost always a solc compile error on that one file (e.g. a
                # `view` function with an inline-assembly `sstore`, which solc
                # rejects). A compiler-based tool legitimately cannot analyze
                # code that does not compile, so record it as an un-analyzable
                # skip instead of failing the whole multi-file case — the
                # expected bugs in that fragment simply become misses for this
                # tool, which is the fair outcome.
                skipped.append(rel_path(target, self.root))
        if expanded and produced == 0:
            # Nothing compiled at all — the tool/toolchain is genuinely broken
            # or misconfigured, not merely tripped by one bad fragment.
            status = "error"
            errors.append("no targets produced output (compiler/tool failure)")
        elif skipped:
            preview = ", ".join(skipped[:5]) + (f" (+{len(skipped) - 5} more)" if len(skipped) > 5 else "")
            errors.append(f"{len(skipped)} fragment(s) not analyzable (solc compile error): {preview}")
        stdout = combine_raw_files(self.raw_dir / f"{case['id']}.slither.stdout", stdout_parts)
        stderr = combine_raw_files(self.raw_dir / f"{case['id']}.slither.stderr", stderr_parts)
        return make_run(self.name, case, last_cmd, aggregate_results(results), stdout, stderr, findings, status, "; ".join(errors))


class SemgrepAdapter(ToolAdapter):
    name = "semgrep"

    def __init__(self, root: Path, out_dir: Path, matcher: AliasMatcher, args: argparse.Namespace) -> None:
        super().__init__(root, out_dir, matcher, args)
        self.binary = find_executable("semgrep")

    def available(self) -> tuple[bool, str]:
        return (True, "") if self.binary else (False, "semgrep is not installed")

    def version(self) -> str:
        return version_from([self.binary, "--version"], self.root)

    def run_case(self, case: dict[str, Any], source: CaseSourceIndex) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        stdout_parts: list[tuple[str, Path]] = []
        stderr_parts: list[tuple[str, Path]] = []
        status = "ok"
        errors: list[str] = []
        last_cmd: list[str] = []
        for target in case_targets(case):
            stem = self.raw_stem(case, target)
            stdout = self.raw_dir / f"{stem}.semgrep.json"
            stderr = self.raw_dir / f"{stem}.semgrep.stderr"
            stdout_parts.append((target, stdout))
            stderr_parts.append((target, stderr))
            semgrep_config = case.get("semgrep_config") or self.args.semgrep_config
            cmd = [self.binary, "scan", "--config", semgrep_config, "--json", target]
            last_cmd = cmd
            result = run_command(cmd, self.root, stdout, stderr, self.args.timeout, {"SEMGREP_SEND_METRICS": "off"})
            results.append(result)
            if result.get("exit_code") not in (0, 1):
                status = "error"
                errors.append(f"semgrep exited with {result.get('exit_code')} for {target}")
            try:
                data = json.loads(stdout.read_text(encoding="utf-8") or "{}")
                config_errors = data.get("errors", [])
                if config_errors:
                    status = "error"
                    for item in config_errors[:3]:
                        message = item.get("message") if isinstance(item, dict) else str(item)
                        errors.append(f"semgrep config error for {target}: {message}")
                for item in data.get("results", []):
                    line = int(item.get("start", {}).get("line") or 0)
                    file_path = item.get("path", target)
                    contract, function = source.lookup(line, file_path)
                    extra = item.get("extra", {})
                    findings.append(
                        self.finding(
                            case,
                            item.get("check_id", ""),
                            file_path,
                            contract,
                            function,
                            line,
                            extra.get("severity", ""),
                            extra.get("message", ""),
                        )
                    )
            except Exception as exc:
                status = "error"
                errors.append(f"could not parse semgrep JSON for {target}: {exc}")
        stdout = combine_raw_files(self.raw_dir / f"{case['id']}.semgrep.json", stdout_parts)
        stderr = combine_raw_files(self.raw_dir / f"{case['id']}.semgrep.stderr", stderr_parts)
        return make_run(self.name, case, last_cmd, aggregate_results(results), stdout, stderr, findings, status, "; ".join(errors))


class AderynAdapter(ToolAdapter):
    name = "aderyn"

    def __init__(self, root: Path, out_dir: Path, matcher: AliasMatcher, args: argparse.Namespace) -> None:
        super().__init__(root, out_dir, matcher, args)
        self.binary = find_executable("aderyn")

    def available(self) -> tuple[bool, str]:
        return (True, "") if self.binary else (False, "aderyn is not installed")

    def version(self) -> str:
        return version_from([self.binary, "--version"], self.root)

    def run_case(self, case: dict[str, Any], source: CaseSourceIndex) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        stdout_parts: list[tuple[str, Path]] = []
        stderr_parts: list[tuple[str, Path]] = []
        status = "ok"
        errors: list[str] = []
        last_cmd: list[str] = []
        for target in case_targets(case):
            stem = self.raw_stem(case, target)
            output = self.raw_dir / f"{stem}.aderyn.json"
            stdout = self.raw_dir / f"{stem}.aderyn.stdout"
            stderr = self.raw_dir / f"{stem}.aderyn.stderr"
            stdout_parts.append((target, stdout))
            stderr_parts.append((target, stderr))
            cmd = [self.binary, "--skip-update-check", "-o", str(output), target]
            last_cmd = cmd
            result = run_command(cmd, self.root, stdout, stderr, self.args.timeout)
            results.append(result)
            if output.exists():
                try:
                    data = json.loads(output.read_text(encoding="utf-8"))
                    for item in flatten_issue_items(data):
                        rule = first_present(item, ["check", "rule", "rule_id", "detector", "title", "name"])
                        line = int(first_present(item, ["line", "startLine", "start_line"]) or 0)
                        file_path = first_present(item, ["file", "path", "source", "source_path"]) or target
                        contract = first_present(item, ["contract", "contract_name"]) or ""
                        function = first_present(item, ["function", "function_name"]) or ""
                        if not contract and line:
                            contract, function = source.lookup(line, str(file_path))
                        findings.append(
                            self.finding(
                                case,
                                str(rule),
                                str(file_path),
                                str(contract),
                                str(function),
                                line,
                                str(first_present(item, ["severity", "impact"]) or ""),
                                str(first_present(item, ["message", "description", "title"]) or ""),
                            )
                        )
                except Exception as exc:
                    status = "error"
                    errors.append(f"could not parse {output}: {exc}")
            else:
                status = "error"
                errors.append(f"expected output was not written: {output}")
        stdout = combine_raw_files(self.raw_dir / f"{case['id']}.aderyn.stdout", stdout_parts)
        stderr = combine_raw_files(self.raw_dir / f"{case['id']}.aderyn.stderr", stderr_parts)
        return make_run(self.name, case, last_cmd, aggregate_results(results), stdout, stderr, findings, status, "; ".join(errors))


class Naly3erAdapter(ToolAdapter):
    """Adapter for 4naly3er (https://github.com/Picodes/4naly3er).

    4naly3er is a Node/TypeScript tool with no published single binary; it is
    normally run from a checkout (`yarn analyze <scope> <out.md>`). We therefore
    take the invocation as a configurable command (``--naly3er-cmd`` or the
    ``W3_NALY3ER_CMD`` env var, default ``4naly3er``) and skip gracefully when it
    is not on PATH — exactly like every other market tool.

    4naly3er emits a Markdown report. Its per-run issue *codes* (`H-1`, `M-2`)
    are positional and unstable, so we key conversion on the issue *title*
    (stable) and let the AliasMatcher map it via the title fragments in
    config/4naly3er/detectors.json. Findings are located by the ``File:`` path
    and the ``NNN:`` line markers 4naly3er prints in its code excerpts; the
    shared SourceIndex then resolves contract/function from the line.
    """

    name = "4naly3er"

    def __init__(self, root: Path, out_dir: Path, matcher: AliasMatcher, args: argparse.Namespace) -> None:
        super().__init__(root, out_dir, matcher, args)
        cmd = getattr(args, "naly3er_cmd", "") or os.environ.get("W3_NALY3ER_CMD", "") or "4naly3er"
        self.cmd = cmd
        self.binary = find_executable(cmd) or (cmd if Path(cmd).exists() else "")

    def available(self) -> tuple[bool, str]:
        return (True, "") if self.binary else (False, f"4naly3er command '{self.cmd}' not found (set --naly3er-cmd or W3_NALY3ER_CMD)")

    def version(self) -> str:
        return version_from([self.binary, "--version"], self.root)

    _HEADER_RX = re.compile(r"^\s*#{1,6}\s*(?:<a\s+name=\"[^\"]*\"></a>)?\s*\[?([HMLN]+-?\d+|GAS-\d+|NC-\d+)\]?\s*(.*?)\s*$")
    _FILE_RX = re.compile(r"\bFile:\s*([^\s`]+\.sol)")
    _LINE_RX = re.compile(r"^\s*(\d+):")

    def run_case(self, case: dict[str, Any], source: CaseSourceIndex) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        stdout_parts: list[tuple[str, Path]] = []
        stderr_parts: list[tuple[str, Path]] = []
        status = "ok"
        errors: list[str] = []
        last_cmd: list[str] = []
        for target in case_targets(case):
            stem = self.raw_stem(case, target)
            report = self.raw_dir / f"{stem}.4naly3er.md"
            stdout = self.raw_dir / f"{stem}.4naly3er.stdout"
            stderr = self.raw_dir / f"{stem}.4naly3er.stderr"
            stdout_parts.append((target, stdout))
            stderr_parts.append((target, stderr))
            # `<cmd> <scope> <out.md>` is the common 4naly3er CLI shape; the
            # report is also echoed to stdout, so we parse whichever exists.
            cmd = [self.binary, target, str(report)]
            last_cmd = cmd
            result = run_command(cmd, self.root, stdout, stderr, self.args.timeout)
            results.append(result)
            text = ""
            if report.exists():
                text = report.read_text(encoding="utf-8", errors="replace")
            if not text:
                text = stdout.read_text(encoding="utf-8", errors="replace")
            if not text.strip():
                status = "error"
                errors.append(f"no 4naly3er report produced for {target}")
                continue
            findings.extend(self._parse_report(case, text, target, source))
        stdout = combine_raw_files(self.raw_dir / f"{case['id']}.4naly3er.stdout", stdout_parts)
        stderr = combine_raw_files(self.raw_dir / f"{case['id']}.4naly3er.stderr", stderr_parts)
        return make_run(self.name, case, last_cmd, aggregate_results(results), stdout, stderr, findings, status, "; ".join(errors))

    def _parse_report(self, case: dict[str, Any], text: str, target: str, source: CaseSourceIndex) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        cur_title = ""
        cur_file = ""
        seen: set[tuple[str, str, int]] = set()
        for raw in text.splitlines():
            header = self._HEADER_RX.match(raw)
            if header:
                # Key on the title (stable) rather than the positional code.
                cur_title = header.group(2).strip() or header.group(1)
                # Strip markdown link syntax from the title.
                cur_title = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", cur_title)
                cur_file = ""
                continue
            file_match = self._FILE_RX.search(raw)
            if file_match:
                cur_file = file_match.group(1)
                continue
            line_match = self._LINE_RX.match(raw)
            if line_match and cur_title:
                line = int(line_match.group(1))
                path = cur_file or target
                dedup = (cur_title, path, line)
                if dedup in seen:
                    continue
                seen.add(dedup)
                contract, function = source.lookup(line, path)
                out.append(self.finding(case, cur_title, path, contract, function, line, "", cur_title))
        return out


ADAPTERS = {
    "w3goaudit": W3GoAuditAdapter,
    "slither": SlitherAdapter,
    "aderyn": AderynAdapter,
    "semgrep": SemgrepAdapter,
    "4naly3er": Naly3erAdapter,
}


def make_run(
    tool: str,
    case: dict[str, Any],
    cmd: list[str],
    result: dict[str, Any],
    stdout: Path,
    stderr: Path,
    findings: list[dict[str, Any]],
    status: str,
    error: str,
) -> dict[str, Any]:
    if result.get("timed_out"):
        status = "error"
        error = "timeout"
    return {
        "tool": tool,
        "case_id": case["id"],
        "status": status,
        "error": error,
        "command": cmd,
        "exit_code": result.get("exit_code"),
        "duration_ms": result.get("duration_ms"),
        "stdout": rel_path(stdout),
        "stderr": rel_path(stderr),
        "raw_findings": len(findings),
        "scoped_findings": sum(1 for item in findings if item.get("category")),
        "findings": findings,
    }


def first_present(item: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        if key in item and item[key] not in (None, ""):
            return item[key]
    return ""


def flatten_issue_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if not isinstance(data, dict):
        return []
    out: list[dict[str, Any]] = []
    for key in ("issues", "findings", "results", "detectors", "highs", "lows"):
        value = data.get(key)
        if isinstance(value, list):
            out.extend(x for x in value if isinstance(x, dict))
        elif isinstance(value, dict):
            out.extend(flatten_issue_items(value))
    return out


def slither_location(item: dict[str, Any]) -> tuple[str, str, int, str]:
    for element in item.get("elements", []):
        contract, function = slither_element_names(element)
        mapping = element.get("source_mapping", {})
        lines = mapping.get("lines") or []
        line = int(lines[0]) if lines else 0
        file_path = mapping.get("filename_absolute") or mapping.get("filename_relative") or ""
        if contract or function or line:
            return contract, function, line, file_path
    return "", "", 0, ""


def slither_element_names(element: dict[str, Any]) -> tuple[str, str]:
    element_type = element.get("type")
    fields = element.get("type_specific_fields") or {}
    if element_type == "function":
        parent = fields.get("parent") or {}
        return parent.get("name", ""), clean_function(element.get("name", ""))
    if element_type == "node":
        parent = fields.get("parent") or {}
        function = clean_function(parent.get("name", ""))
        parent_fields = parent.get("type_specific_fields") or {}
        contract = (parent_fields.get("parent") or {}).get("name", "")
        return contract, function
    if element_type == "variable":
        parent = fields.get("parent") or {}
        return parent.get("name", ""), ""
    return "", clean_function(element.get("name", ""))


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
    # This is the "same bug, different attribution" fix — without it Slither
    # reporting at `_internalDeposit` while the corpus expected the entry
    # function `depositFrom` would land as FP+FN even though the bug WAS
    # detected (see call_chain.py).
    chains_by_case = chains_by_case or {}
    expected = expected_keys(corpus)
    actual_map: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
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
    f1 = 2 * precision * detection_rate / (precision + detection_rate) if precision + detection_rate else 0.0
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
    if status == "skipped":
        return "skipped"
    if status == "error":
        return "failed"
    return status or "unknown"


def write_markdown(report: dict[str, Any], path: Path) -> None:
    lines: list[str] = []
    expected_total = sum(len(case.get("expected", [])) for case in report["corpus"].get("cases", []))
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
    lines.append("It runs each tool on Solidity files with known bugs, compares tool findings with the corpus answer key, then reports:")
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
        if info["status"] == "skipped":
            lines.append(f"- `{tool}` was skipped: {info.get('reason', 'not available')}.")
            continue
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
    lines.append("| Tool | Status | Found Bugs | Extra Noise | Missed Bugs | Precision | Detection Rate | F1 |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|")
    for tool, info in report["tools"].items():
        if info["status"] == "skipped":
            lines.append(f"| {tool} | skipped | - | - | - | - | - | - |")
            continue
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
    lines.append("| Tool | Bug Type | Found | Noise | Missed | Precision | Detection Rate | F1 |")
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
    lines.append("These are benchmark-category findings that were not in the corpus answer key. They are noise for scoring, but some may still be real bugs if the answer key is incomplete.")
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
    lines.append(f"| `{rel_path(path.with_name('benchmark.json'))}` | The same result as JSON for scripts or dashboards. |")
    lines.append(f"| `{rel_path(path.parent / 'raw')}/` | Raw output from each tool and case, useful when debugging a failed run. |")
    lines.append("")
    lines.append("## Run Details")
    lines.append("")
    lines.append("Use this section when a tool was skipped, failed, or returned strange results.")
    lines.append("")
    lines.append("| Tool | Case | Status | Exit | Runtime ms | Raw | Scoped | Error |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---|")
    for run in report["runs"]:
        lines.append(
            f"| {run['tool']} | {run['case_id']} | {short_status(run['status'])} | {run.get('exit_code')} | {run.get('duration_ms')} | {run.get('raw_findings')} | {run.get('scoped_findings')} | {md_escape(run.get('error', ''))} |"
        )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


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
        default="benchmarks/config",
        help="directory holding per-tool detector manifests (config/<tool>/detectors.json)",
    )
    parser.add_argument(
        "--semgrep-config",
        default="benchmarks/config/semgrep-decurity",
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
    out_dir = repo_path(args.out, root)
    raw_dir = out_dir / "raw"
    # Raw files are per-run evidence. Clear old raw logs so skipped tools do
    # not leave confusing stale files from a previous benchmark.
    if raw_dir.exists():
        shutil.rmtree(raw_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)
    corpus_path = args.corpus or SUITES[args.suite]
    corpus = json.loads(repo_path(corpus_path, root).read_text(encoding="utf-8"))
    selected = [name.strip() for name in args.tools.split(",") if name.strip()]
    unknown = [name for name in selected if name not in ADAPTERS]
    if unknown:
        raise SystemExit(f"unknown tools: {', '.join(unknown)}")
    # Auto-load per-tool detector manifests so a tool's native check IDs map onto
    # shared categories even when the corpus omits an explicit alias for them.
    manifest_aliases = load_tool_manifests(args.config_dir, selected, root)
    matcher = AliasMatcher(corpus, manifest_aliases)

    source_indexes = {
        case["id"]: CaseSourceIndex(case_targets(case), root)
        for case in corpus.get("cases", [])
    }

    tools: dict[str, dict[str, Any]] = {}
    runs: list[dict[str, Any]] = []
    metrics: dict[str, dict[str, Any]] = {}

    # Per-case internal-call graphs, built lazily after w3goaudit prepare()
    # runs. Used to relax (case, category, contract, function) matching when
    # two tools attribute the same bug at different points on the same chain.
    chains_by_case: dict[str, dict[str, dict[str, set[str]]]] = {}
    w3_chain_dir = out_dir / "raw" / ".callgraphs"

    for name in selected:
        adapter = ADAPTERS[name](root, out_dir, matcher, args)
        available, reason = adapter.available()
        if not available:
            tools[name] = {"status": "skipped", "reason": reason, "version": ""}
            continue
        try:
            adapter.prepare()
            version = adapter.version()
            tools[name] = {"status": "ok", "reason": "", "version": version}
        except Exception as exc:
            tools[name] = {"status": "skipped", "reason": str(exc), "version": ""}
            continue

        # First time the w3goaudit adapter is ready, use its binary to build
        # one call graph per case. Failing silently is fine — scoring falls
        # back to strict equality if a case's graph isn't available.
        if name == "w3goaudit" and not chains_by_case:
            for case in corpus.get("cases", []):
                db_path = call_chain.build_case_database(
                    case, root, adapter.binary, w3_chain_dir
                )
                graph = call_chain.load_case_chain_db(db_path)
                if graph is not None:
                    chains_by_case[case["id"]] = graph

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
    shutil.rmtree(raw_dir / ".bin", ignore_errors=True)
    print(f"Wrote {rel_path(out_dir / 'benchmark.md', root)}")
    print(f"Wrote {rel_path(out_dir / 'benchmark.json', root)}")
    for tool, block in metrics.items():
        print(
            f"{tool}: precision={block['precision']:.2%} detection_rate={block['detection_rate']:.2%} "
            f"f1={block['f1']:.2%} raw={block['raw_findings']} scoped={block['unique_scoped_findings']}"
        )
    skipped = {tool: info["reason"] for tool, info in tools.items() if info["status"] == "skipped"}
    if skipped:
        print("Skipped:", json.dumps(skipped, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
