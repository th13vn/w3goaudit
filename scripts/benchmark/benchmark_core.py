from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Protocol


ROOT = Path(__file__).resolve().parents[2]

TOOL_EXECUTABLES = {
    "w3goaudit": "w3goaudit",
    "slither": "slither",
    "semgrep": "semgrep",
    "4naly3er": "4naly3er",
    "aderyn": "aderyn",
}


def find_executable(name: str) -> str:
    return shutil.which(name) or ""


def require_tools(
    names: list[str], overrides: dict[str, str] | None = None
) -> dict[str, str]:
    """Resolve every requested scanner from PATH before benchmark work starts."""
    overrides = overrides or {}
    resolved: dict[str, str] = {}
    for name in names:
        executable = overrides.get(name) or TOOL_EXECUTABLES[name]
        found = find_executable(executable)
        if not found:
            raise RuntimeError(f"requested tool {name} is unavailable")
        resolved[name] = found
    return resolved


def resolve_output_path(results_root: Path, value: str | Path) -> Path:
    """Resolve an output path while keeping it inside the mounted result root."""
    root = results_root.resolve()
    path = Path(value)
    candidate = (path if path.is_absolute() else root / path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"output path {candidate} is outside benchmark results root {root}"
        ) from exc
    return candidate


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
    independently (Slither/4naly3er): when the corpus target is a directory,
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
            out.extend(
                rel_path(p, root)
                for p in sorted(path.rglob("*.sol"))
                if p.is_file()
            )
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


def sanitize_solidity_source(source: str) -> str:
    """Mask Solidity comments and quoted strings without moving positions."""
    masked: list[str] = []
    state = "code"
    index = 0
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""

        if state == "code":
            if char == "/" and next_char == "/":
                masked.extend((" ", " "))
                state = "line_comment"
                index += 2
                continue
            if char == "/" and next_char == "*":
                masked.extend((" ", " "))
                state = "block_comment"
                index += 2
                continue
            if char == "'":
                masked.append(" ")
                state = "single_quote"
                index += 1
                continue
            if char == '"':
                masked.append(" ")
                state = "double_quote"
                index += 1
                continue
            masked.append(char)
            index += 1
            continue

        if state == "line_comment":
            if char in "\r\n":
                masked.append(char)
                state = "code"
            else:
                masked.append(" ")
            index += 1
            continue

        if state == "block_comment":
            if char == "*" and next_char == "/":
                masked.extend((" ", " "))
                state = "code"
                index += 2
                continue
            masked.append(char if char in "\r\n" else " ")
            index += 1
            continue

        quote = "'" if state == "single_quote" else '"'
        if char == "\\":
            masked.append(" ")
            index += 1
            if index < len(source):
                escaped = source[index]
                masked.append(escaped if escaped in "\r\n" else " ")
                index += 1
            continue
        if char == quote:
            masked.append(" ")
            state = "code"
            index += 1
            continue
        masked.append(char if char in "\r\n" else " ")
        index += 1

    return "".join(masked)


class SourceIndex:
    """Tiny Solidity source index used to map line numbers back to names.

    Some tools only report "line 123". The benchmark needs "Contract.function"
    to compare that alert with the expected labels, so this helper scans the
    source text and builds rough contract/function ranges.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        source = path.read_text(encoding="utf-8")
        self.lines = source.splitlines()
        self.sanitized_lines = sanitize_solidity_source(source).splitlines()
        self.contracts = self._build_ranges(
            r"\b(contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)"
        )
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
        for idx, text in enumerate(self.sanitized_lines):
            match = rx.search(text)
            if match:
                name = match.group(2)
                out.append((idx + 1, self._block_end(idx), name))
        return out

    def _build_function_ranges(self) -> list[tuple[int, int, str]]:
        out: list[tuple[int, int, str]] = []
        function_rx = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)")
        special_rx = re.compile(r"^\s*(receive|fallback)\s*\(")
        for idx, text in enumerate(self.sanitized_lines):
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
        for idx in range(start_idx, len(self.sanitized_lines)):
            text = self.sanitized_lines[idx]
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
        return len(self.sanitized_lines)


class CaseSourceIndex:
    """Source lookup for a benchmark case.

    A case may contain one target file or many target files. This wrapper picks
    the right SourceIndex based on the file path reported by a tool.
    """

    def __init__(self, targets: list[str], root: Path) -> None:
        self.root = root
        self.sources: list[SourceIndex] = []
        self.by_relative_path: dict[str, SourceIndex] = {}
        self.by_absolute_path: dict[str, SourceIndex] = {}
        self.by_basename: dict[str, list[SourceIndex]] = defaultdict(list)
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
        seen: set[str] = set()
        for path in files:
            absolute_path = str(path.resolve())
            if absolute_path in seen:
                continue
            seen.add(absolute_path)
            index = SourceIndex(path)
            self.sources.append(index)
            self.by_relative_path[rel_path(path, root)] = index
            self.by_absolute_path[absolute_path] = index
            self.by_basename[path.name].append(index)

    def lookup(
        self, line: int | None, file_path: str | None = None
    ) -> tuple[str, str]:
        if not line:
            return "", ""
        index = self._index_for(file_path)
        return index.lookup(line) if index else ("", "")

    def _index_for(self, file_path: str | None) -> SourceIndex | None:
        if file_path:
            rel = rel_path(file_path, self.root)
            if rel in self.by_relative_path:
                return self.by_relative_path[rel]
            try:
                abs_path = str(repo_path(file_path, self.root).resolve())
                if abs_path in self.by_absolute_path:
                    return self.by_absolute_path[abs_path]
            except Exception:
                pass
            matches = self.by_basename.get(Path(file_path).name, [])
            if len(matches) == 1:
                return matches[0]
        return self.sources[0] if len(self.sources) == 1 else None


class AliasMatcher:
    """Maps each tool's rule names onto our shared benchmark categories.

    Example: W3GoAudit may report SEC-GEN-REENTRANCY while Slither reports
    reentrancy-eth. The corpus says both aliases mean category "reentrancy".
    """

    def __init__(
        self,
        corpus: dict[str, Any],
        manifest_aliases: dict[str, list[tuple[str, str]]] | None = None,
    ) -> None:
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
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with stdout_path.open("w", encoding="utf-8") as stdout_file, stderr_path.open(
            "w", encoding="utf-8"
        ) as stderr_file:
            proc = subprocess.run(
                cmd,
                cwd=str(cwd),
                stdout=stdout_file,
                stderr=stderr_file,
                text=True,
                timeout=timeout,
                env=merged_env,
            )
        return {
            "exit_code": proc.returncode,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        with stderr_path.open("a", encoding="utf-8") as stderr_file:
            stderr_file.write("\nTIMEOUT\n")
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
        "duration_ms": round(
            sum(float(result.get("duration_ms") or 0) for result in results), 2
        ),
        "timed_out": any(result.get("timed_out") for result in results),
    }


def combine_raw_files(dest: Path, parts: list[tuple[str, Path]]) -> Path:
    if len(parts) == 1:
        return parts[0][1]
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as combined:
        for index, (target, path) in enumerate(parts):
            if index:
                combined.write("\n")
            combined.write(f"===== {target} :: {path.name} =====\n")
            try:
                ends_with_newline = _file_ends_with_newline(path)
                with path.open("r", encoding="utf-8") as source:
                    shutil.copyfileobj(source, combined)
            except Exception as exc:
                combined.write(f"<could not read {path}: {exc}>\n")
                ends_with_newline = True
            if not ends_with_newline:
                combined.write("\n")
    return dest


def _file_ends_with_newline(path: Path) -> bool:
    with path.open("rb") as stream:
        if stream.seek(0, os.SEEK_END) == 0:
            return False
        stream.seek(-1, os.SEEK_END)
        return stream.read(1) == b"\n"


def slither_proves_solc_failure(stdout: Path, stderr: Path) -> bool:
    """Return true only for diagnostics that identify a Solidity compiler failure."""
    diagnostic = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        if path.exists()
        else ""
        for path in (stdout, stderr)
    ).lower()
    markers = (
        "compilation warnings/errors on",
        "invalid solc compilation",
        "solc compilation error",
        "solc returned an error",
        "solidity compilation failed",
        "crytic_compile.platform.exceptions.invalidcompilation",
    )
    return any(marker in diagnostic for marker in markers)


def naly3er_proves_solc_failure(stdout: Path, stderr: Path) -> bool:
    """Require both 4naly3er's AST failure and a structured compiler error."""
    diagnostic = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        if path.exists()
        else ""
        for path in (stdout, stderr)
    )
    cannot_compile = re.search(r"\bCannot compile AST for\b", diagnostic) is not None
    structured_severity = (
        re.search(
            r'''["']?severity["']?\s*:\s*["']error["']''',
            diagnostic,
            re.IGNORECASE,
        )
        is not None
    )
    structured_type = (
        re.search(
            r'''["']?type["']?\s*:\s*["'][A-Za-z]*(?:Error|Exception)["']''',
            diagnostic,
            re.IGNORECASE,
        )
        is not None
    )
    return cannot_compile and structured_severity and structured_type


def version_from(cmd: list[str], cwd: Path, timeout: int = 30) -> str:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
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


class BenchmarkAdapter(Protocol):
    def available(self) -> tuple[bool, str]: ...

    def prepare(self) -> None: ...

    def version(self) -> str: ...


def prepare_requested_tool(
    name: str, adapter: BenchmarkAdapter
) -> dict[str, str]:
    available, reason = adapter.available()
    if not available:
        detail = f": {reason}" if reason else ""
        raise RuntimeError(f"requested tool {name} is unavailable{detail}")
    try:
        adapter.prepare()
    except Exception as exc:
        raise RuntimeError(
            f"failed to prepare requested tool {name}: {exc}"
        ) from exc
    return {"status": "ok", "reason": "", "version": adapter.version()}


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
