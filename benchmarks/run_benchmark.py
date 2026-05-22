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
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


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
    targets = case.get("targets")
    if isinstance(targets, list) and targets:
        return [str(target) for target in targets]
    return [str(case["target"])]


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
    def __init__(self, targets: list[str], root: Path) -> None:
        self.root = root
        self.default: SourceIndex | None = None
        self.by_path: dict[str, SourceIndex] = {}
        for target in targets:
            path = repo_path(target, root)
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
    def __init__(self, corpus: dict[str, Any]) -> None:
        self.by_tool: dict[str, dict[str, str]] = defaultdict(dict)
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


class ToolAdapter:
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
        self.binary = Path(args.w3goaudit_bin) if args.w3goaudit_bin else out_dir / "bin" / "w3goaudit"

    def available(self) -> tuple[bool, str]:
        if self.binary.exists():
            return True, ""
        if not shutil.which("go"):
            return False, "go is not installed and --w3goaudit-bin was not provided"
        return True, ""

    def prepare(self) -> None:
        if self.args.w3goaudit_bin and self.binary.exists():
            return
        self.binary.parent.mkdir(parents=True, exist_ok=True)
        stdout = self.raw_dir / "w3goaudit-build.stdout"
        stderr = self.raw_dir / "w3goaudit-build.stderr"
        result = run_command(
            ["go", "build", "-o", str(self.binary), "./cmd/w3goaudit"],
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
            base = self.raw_dir / f"{stem}.w3goaudit.json"
            stdout = self.raw_dir / f"{stem}.w3goaudit.stdout"
            stderr = self.raw_dir / f"{stem}.w3goaudit.stderr"
            stdout_parts.append((target, stdout))
            stderr_parts.append((target, stderr))
            cmd = [
                str(self.binary),
                target,
                "--template",
                case["templates"],
                "--json",
                "-o",
                str(base),
            ]
            last_cmd = cmd
            result = run_command(cmd, self.root, stdout, stderr, self.args.timeout)
            results.append(result)
            findings_path = base.with_name(base.stem + ".findings.json")
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

    def available(self) -> tuple[bool, str]:
        return (True, "") if shutil.which("slither") else (False, "slither is not installed")

    def version(self) -> str:
        return version_from(["slither", "--version"], self.root)

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
            output = self.raw_dir / f"{stem}.slither.json"
            stdout = self.raw_dir / f"{stem}.slither.stdout"
            stderr = self.raw_dir / f"{stem}.slither.stderr"
            stdout_parts.append((target, stdout))
            stderr_parts.append((target, stderr))
            cmd = ["slither", target, "--json", str(output)]
            last_cmd = cmd
            result = run_command(cmd, self.root, stdout, stderr, self.args.timeout)
            results.append(result)
            if output.exists():
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
                status = "error"
                errors.append(f"expected output was not written: {output}")
        stdout = combine_raw_files(self.raw_dir / f"{case['id']}.slither.stdout", stdout_parts)
        stderr = combine_raw_files(self.raw_dir / f"{case['id']}.slither.stderr", stderr_parts)
        return make_run(self.name, case, last_cmd, aggregate_results(results), stdout, stderr, findings, status, "; ".join(errors))


class SolhintAdapter(ToolAdapter):
    name = "solhint"

    def __init__(self, root: Path, out_dir: Path, matcher: AliasMatcher, args: argparse.Namespace) -> None:
        super().__init__(root, out_dir, matcher, args)
        if shutil.which("solhint"):
            self.prefix = ["solhint"]
        elif args.allow_npx and shutil.which("npx"):
            self.prefix = ["npx", "--yes", "solhint"]
        else:
            self.prefix = []

    def available(self) -> tuple[bool, str]:
        if self.prefix:
            return True, ""
        return False, "solhint is not installed (pass --allow-npx to run it through npx)"

    def version(self) -> str:
        return version_from(self.prefix + ["--version"], self.root)

    def run_case(self, case: dict[str, Any], source: CaseSourceIndex) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        stdout_parts: list[tuple[str, Path]] = []
        stderr_parts: list[tuple[str, Path]] = []
        status = "ok"
        errors: list[str] = []
        last_cmd: list[str] = []
        config = rel_path(self.args.solhint_config, self.root)
        for target in case_targets(case):
            stem = self.raw_stem(case, target)
            stdout = self.raw_dir / f"{stem}.solhint.json"
            stderr = self.raw_dir / f"{stem}.solhint.stderr"
            stdout_parts.append((target, stdout))
            stderr_parts.append((target, stderr))
            cmd = self.prefix + ["-f", "json", "-c", config, target]
            last_cmd = cmd
            result = run_command(cmd, self.root, stdout, stderr, self.args.timeout)
            results.append(result)
            try:
                data = json.loads(stdout.read_text(encoding="utf-8") or "[]")
                items = data if isinstance(data, list) else data.get("reports", [])
                for item in items:
                    line = int(item.get("line") or 0)
                    file_path = item.get("filePath", target)
                    contract, function = source.lookup(line, file_path)
                    findings.append(
                        self.finding(
                            case,
                            item.get("ruleId", ""),
                            file_path,
                            contract,
                            function,
                            line,
                            item.get("severity", ""),
                            item.get("message", ""),
                        )
                    )
            except Exception as exc:
                status = "error"
                errors.append(f"could not parse solhint JSON for {target}: {exc}")
        stdout = combine_raw_files(self.raw_dir / f"{case['id']}.solhint.json", stdout_parts)
        stderr = combine_raw_files(self.raw_dir / f"{case['id']}.solhint.stderr", stderr_parts)
        return make_run(self.name, case, last_cmd, aggregate_results(results), stdout, stderr, findings, status, "; ".join(errors))


class SemgrepAdapter(ToolAdapter):
    name = "semgrep"

    def available(self) -> tuple[bool, str]:
        return (True, "") if shutil.which("semgrep") else (False, "semgrep is not installed")

    def version(self) -> str:
        return version_from(["semgrep", "--version"], self.root)

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
            cmd = ["semgrep", "scan", "--config", self.args.semgrep_config, "--json", target]
            last_cmd = cmd
            result = run_command(cmd, self.root, stdout, stderr, self.args.timeout, {"SEMGREP_SEND_METRICS": "off"})
            results.append(result)
            try:
                data = json.loads(stdout.read_text(encoding="utf-8") or "{}")
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

    def available(self) -> tuple[bool, str]:
        return (True, "") if shutil.which("aderyn") else (False, "aderyn is not installed")

    def version(self) -> str:
        return version_from(["aderyn", "--version"], self.root)

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
            cmd = ["aderyn", "--skip-update-check", "-o", str(output), target]
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


ADAPTERS = {
    "w3goaudit": W3GoAuditAdapter,
    "slither": SlitherAdapter,
    "aderyn": AderynAdapter,
    "semgrep": SemgrepAdapter,
    "solhint": SolhintAdapter,
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


def evaluate_tool(tool: str, runs: list[dict[str, Any]], corpus: dict[str, Any]) -> dict[str, Any]:
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
    tp = sorted(expected & actual)
    fp = sorted(actual - expected)
    fn = sorted(expected - actual)
    metrics = metric_block(len(tp), len(fp), len(fn))
    by_category = {}
    categories = sorted(corpus.get("categories", {}).keys())
    for category in categories:
        exp_c = {key for key in expected if key[1] == category}
        act_c = {key for key in actual if key[1] == category}
        tp_c = exp_c & act_c
        fp_c = act_c - exp_c
        fn_c = exp_c - act_c
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
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def key_to_dict(key: tuple[str, str, str, str]) -> dict[str, str]:
    return {
        "case_id": key[0],
        "category": key[1],
        "contract": key[2],
        "function": key[3],
    }


def write_markdown(report: dict[str, Any], path: Path) -> None:
    lines: list[str] = []
    lines.append("# Static Analyzer Benchmark")
    lines.append("")
    lines.append(f"- Generated: `{report['generated_at']}`")
    lines.append(f"- Corpus: `{report['corpus']['name']}`")
    lines.append(f"- Cases: `{len(report['corpus']['cases'])}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Tool | Status | Version | Cases | Runtime ms | Raw | Scoped | Precision | Recall | F1 |")
    lines.append("|---|---:|---|---:|---:|---:|---:|---:|---:|---:|")
    for tool, info in report["tools"].items():
        if info["status"] == "skipped":
            lines.append(f"| {tool} | skipped | {info.get('version', '')} | 0 | 0 | 0 | 0 | - | - | - |")
            continue
        metrics = report["metrics"].get(tool, {})
        lines.append(
            "| {tool} | {status} | {version} | {cases} | {duration} | {raw} | {scoped} | {precision:.2%} | {recall:.2%} | {f1:.2%} |".format(
                tool=tool,
                status=metrics.get("status", info["status"]),
                version=info.get("version", "unknown").replace("|", "\\|"),
                cases=metrics.get("cases", 0),
                duration=metrics.get("duration_ms", 0),
                raw=metrics.get("raw_findings", 0),
                scoped=metrics.get("unique_scoped_findings", 0),
                precision=metrics.get("precision", 0),
                recall=metrics.get("recall", 0),
                f1=metrics.get("f1", 0),
            )
        )
    lines.append("")
    lines.append("## By Category")
    lines.append("")
    lines.append("| Tool | Category | TP | FP | FN | Precision | Recall | F1 |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|")
    for tool, metrics in report["metrics"].items():
        for category, block in metrics.get("by_category", {}).items():
            lines.append(
                f"| {tool} | {category} | {block['tp']} | {block['fp']} | {block['fn']} | {block['precision']:.2%} | {block['recall']:.2%} | {block['f1']:.2%} |"
            )
    lines.append("")
    lines.append("## Misses And Noise")
    lines.append("")
    for tool, metrics in report["metrics"].items():
        lines.append(f"### {tool}")
        lines.append("")
        false_negatives = metrics.get("false_negatives", [])
        false_positives = metrics.get("false_positives", [])
        lines.append(f"- False negatives: `{len(false_negatives)}`")
        for item in false_negatives[:12]:
            lines.append(f"  - `{item['case_id']}` `{item['category']}` `{item['contract']}.{item['function']}()`")
        if len(false_negatives) > 12:
            lines.append(f"  - ... {len(false_negatives) - 12} more")
        lines.append(f"- False positives: `{len(false_positives)}`")
        for item in false_positives[:12]:
            lines.append(f"  - `{item['case_id']}` `{item['category']}` `{item['contract']}.{item['function']}()`")
        if len(false_positives) > 12:
            lines.append(f"  - ... {len(false_positives) - 12} more")
        lines.append("")
    lines.append("## Run Status")
    lines.append("")
    lines.append("| Tool | Case | Status | Exit | Runtime ms | Raw | Scoped | Error |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---|")
    for run in report["runs"]:
        lines.append(
            f"| {run['tool']} | {run['case_id']} | {run['status']} | {run.get('exit_code')} | {run.get('duration_ms')} | {run.get('raw_findings')} | {run.get('scoped_findings')} | {run.get('error', '').replace('|', '/')} |"
        )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark w3goaudit against Solidity static analyzers.")
    parser.add_argument("--root", default=str(ROOT), help="repository root")
    parser.add_argument("--corpus", default="benchmarks/security-corpus.json", help="benchmark corpus JSON")
    parser.add_argument("--out", default="benchmark-results/latest", help="output directory")
    parser.add_argument(
        "--tools",
        default="w3goaudit,slither,aderyn,semgrep,solhint",
        help="comma-separated tool list",
    )
    parser.add_argument("--timeout", type=int, default=180, help="per-tool per-case timeout in seconds")
    parser.add_argument("--w3goaudit-bin", default="", help="use an existing w3goaudit binary")
    parser.add_argument("--allow-npx", action="store_true", help="allow solhint execution through npx when not globally installed")
    parser.add_argument("--semgrep-config", default="p/solidity", help="Semgrep config or registry ruleset")
    parser.add_argument("--solhint-config", default="benchmarks/solhint-recommended.json", help="Solhint config file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    out_dir = repo_path(args.out, root)
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    corpus = json.loads(repo_path(args.corpus, root).read_text(encoding="utf-8"))
    matcher = AliasMatcher(corpus)
    selected = [name.strip() for name in args.tools.split(",") if name.strip()]
    unknown = [name for name in selected if name not in ADAPTERS]
    if unknown:
        raise SystemExit(f"unknown tools: {', '.join(unknown)}")

    source_indexes = {
        case["id"]: CaseSourceIndex(case_targets(case), root)
        for case in corpus.get("cases", [])
    }

    tools: dict[str, dict[str, Any]] = {}
    runs: list[dict[str, Any]] = []
    metrics: dict[str, dict[str, Any]] = {}

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

        tool_runs = []
        for case in corpus.get("cases", []):
            run = adapter.run_case(case, source_indexes[case["id"]])
            runs.append(run)
            tool_runs.append(run)
        metrics[name] = evaluate_tool(name, tool_runs, corpus)

    report = {
        "schema_version": "1.0",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "root": str(root),
        "corpus": {
            "name": corpus.get("name", ""),
            "description": corpus.get("description", ""),
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
            f"{tool}: precision={block['precision']:.2%} recall={block['recall']:.2%} "
            f"f1={block['f1']:.2%} raw={block['raw_findings']} scoped={block['unique_scoped_findings']}"
        )
    skipped = {tool: info["reason"] for tool, info in tools.items() if info["status"] == "skipped"}
    if skipped:
        print("Skipped:", json.dumps(skipped, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
