#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from benchmark_core import (
    AliasMatcher,
    CaseSourceIndex,
    aggregate_results,
    case_targets,
    clean_function,
    combine_raw_files,
    expanded_solc_targets,
    make_run,
    naly3er_proves_solc_failure,
    rel_path,
    run_command,
    safe_path_slug,
    slither_proves_solc_failure,
    version_from,
)

SEMGREP_SUCCESS_EXIT_CODES = {0, 1}


def _fragment_stem(case: dict[str, Any], target: str, multi: bool) -> str:
    if not multi:
        return case["id"]
    return f"{case['id']}__{safe_path_slug(target)}"


def _skipped_fragment_summary(skipped: list[str]) -> str:
    preview = ", ".join(skipped[:5])
    if len(skipped) > 5:
        preview += f" (+{len(skipped) - 5} more)"
    return (
        f"{len(skipped)} fragment(s) not analyzable "
        f"(solc compile error): {preview}"
    )


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
        self.binary = Path(args.resolved_tools[self.name])

    def available(self) -> tuple[bool, str]:
        return (True, "") if self.binary.exists() else (False, "binary not found")

    def version(self) -> str:
        return version_from([str(self.binary), "version"], self.root)

    def command_for(self, target: str, templates: str, outdir: Path) -> list[str]:
        return [
            str(self.binary),
            target,
            "-t",
            templates,
            "-o",
            str(outdir),
        ]

    @staticmethod
    def _resolve_findings_path(outdir: Path) -> Path:
        """Locate the machine-readable findings file in a result folder.

        Prefers the manifest's declared path (data/manifest.json ->
        files.data.findings), then the current standardized location
        (data/findings.json), then the pre-v0.4 layout (corpus/findings.json).
        Returns the canonical data/findings.json for a clear error message when
        none exist.
        """
        manifest = outdir / "data" / "manifest.json"
        if manifest.exists():
            try:
                m = json.loads(manifest.read_text(encoding="utf-8"))
                rel = m.get("files", {}).get("data", {}).get("findings")
                if rel:
                    p = outdir / rel
                    if p.exists():
                        return p
            except Exception:
                pass
        for rel in ("data/findings.json", "corpus/findings.json"):
            p = outdir / rel
            if p.exists():
                return p
        return outdir / "data" / "findings.json"

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
            # Since the v0.4 standardized layout the machine-readable findings
            # land at <out>/data/findings.json (was <out>/corpus/findings.json).
            outdir = self.raw_dir / f"{stem}.w3goaudit.out"
            stdout = self.raw_dir / f"{stem}.w3goaudit.stdout"
            stderr = self.raw_dir / f"{stem}.w3goaudit.stderr"
            stdout_parts.append((target, stdout))
            stderr_parts.append((target, stderr))
            cmd = self.command_for(target, case["templates"], outdir)
            last_cmd = cmd
            result = run_command(cmd, self.root, stdout, stderr, self.args.timeout)
            results.append(result)
            exit_code = result.get("exit_code")
            if exit_code not in (0, None):
                status = "error"
                errors.append(f"w3goaudit exited with {exit_code} for {target}")
            findings_path = self._resolve_findings_path(outdir)
            if findings_path is not None and findings_path.exists():
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
        self.binary = args.resolved_tools[self.name]

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
            stem = _fragment_stem(case, target, multi)
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
                    # Slither can be configured to use a nonzero finding-policy
                    # exit even after writing a successful JSON result. Treat a
                    # nonzero exit as fatal only when the JSON does not affirm
                    # that analysis itself succeeded. An explicit success:false
                    # is always an analysis failure, regardless of process exit.
                    if data.get("success") is False:
                        status = "error"
                        errors.append(f"slither reported unsuccessful analysis for {target}")
                    elif result.get("exit_code") not in (0, None) and data.get("success") is not True:
                        status = "error"
                        errors.append(
                            f"slither exited with {result.get('exit_code')} for {target}"
                        )
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
                # Missing JSON is an error unless the captured diagnostics prove
                # that solc rejected this particular fragment. Runtime crashes,
                # timeouts, and unexplained exits must fail the aggregate case.
                if slither_proves_solc_failure(stdout, stderr):
                    skipped.append(rel_path(target, self.root))
                else:
                    status = "error"
                    reason = "timed out" if result.get("timed_out") else f"exited with {result.get('exit_code')}"
                    errors.append(
                        f"slither failed without compiler diagnostics ({reason}) for {target}"
                    )
        if produced == 0:
            # Nothing compiled at all — the tool/toolchain is genuinely broken
            # or misconfigured, not merely tripped by one bad fragment.
            status = "error"
            errors.append("no targets produced output (compiler/tool failure)")
        elif skipped:
            errors.append(_skipped_fragment_summary(skipped))
        stdout = combine_raw_files(self.raw_dir / f"{case['id']}.slither.stdout", stdout_parts)
        stderr = combine_raw_files(self.raw_dir / f"{case['id']}.slither.stderr", stderr_parts)
        return make_run(self.name, case, last_cmd, aggregate_results(results), stdout, stderr, findings, status, "; ".join(errors))


class SemgrepAdapter(ToolAdapter):
    name = "semgrep"

    def __init__(self, root: Path, out_dir: Path, matcher: AliasMatcher, args: argparse.Namespace) -> None:
        super().__init__(root, out_dir, matcher, args)
        self.binary = args.resolved_tools[self.name]

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
            # Semgrep reserves exit 1 for findings in fail-on-findings modes;
            # accepting it avoids turning a valid findings report into a tool
            # failure. Exit 2+ remains a scan/config/runtime error.
            if result.get("exit_code") not in SEMGREP_SUCCESS_EXIT_CODES:
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
        self.binary = args.resolved_tools[self.name]

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
    ``W3_NALY3ER_CMD`` env var, default ``4naly3er``). Requested tools are
    resolved before any benchmark cases run, so a missing command is fatal.

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
        self.binary = args.resolved_tools[self.name]

    def available(self) -> tuple[bool, str]:
        return (True, "") if self.binary else (False, "4naly3er command not found")

    def version(self) -> str:
        return version_from([self.binary, "--version"], self.root)

    def command_for(self, target: str, report: Path) -> list[str]:
        return [self.binary, target, str(report)]

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
        skipped: list[str] = []
        produced = 0
        last_cmd: list[str] = []
        expanded = expanded_solc_targets(case, self.root)
        multi = len(expanded) > 1
        for target in expanded:
            stem = _fragment_stem(case, target, multi)
            report = self.raw_dir / f"{stem}.4naly3er.md"
            stdout = self.raw_dir / f"{stem}.4naly3er.stdout"
            stderr = self.raw_dir / f"{stem}.4naly3er.stderr"
            stdout_parts.append((target, stdout))
            stderr_parts.append((target, stderr))
            # `<cmd> <scope> <out.md>` is the common 4naly3er CLI shape; the
            # report is also echoed to stdout, so we parse whichever exists.
            cmd = self.command_for(target, report)
            last_cmd = cmd
            result = run_command(cmd, self.root, stdout, stderr, self.args.timeout)
            results.append(result)
            text = ""
            if report.exists():
                text = report.read_text(encoding="utf-8", errors="replace")
            if not text:
                stdout_text = stdout.read_text(encoding="utf-8", errors="replace")
                if re.search(r"(?m)^\s*#\s+Report\s*$", stdout_text) or self._HEADER_RX.search(stdout_text):
                    text = stdout_text
            if not text.strip():
                if not result.get("timed_out") and naly3er_proves_solc_failure(stdout, stderr):
                    skipped.append(rel_path(target, self.root))
                else:
                    status = "error"
                    reason = "timed out" if result.get("timed_out") else f"exited with {result.get('exit_code')}"
                    errors.append(
                        f"4naly3er failed without compiler diagnostics ({reason}) for {target}"
                    )
                continue
            produced += 1
            exit_code = result.get("exit_code")
            if exit_code not in (0, None):
                status = "error"
                errors.append(f"4naly3er exited with {exit_code} for {target}")
            findings.extend(self._parse_report(case, text, target, source))
        if produced == 0:
            status = "error"
            errors.append("no targets produced output (compiler/tool failure)")
        elif skipped:
            errors.append(_skipped_fragment_summary(skipped))
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


ADAPTERS: dict[str, type[ToolAdapter]] = {
    "w3goaudit": W3GoAuditAdapter,
    "slither": SlitherAdapter,
    "aderyn": AderynAdapter,
    "semgrep": SemgrepAdapter,
    "4naly3er": Naly3erAdapter,
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
