import json
import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


BENCHMARKS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(BENCHMARKS))

import benchmark_adapters  # noqa: E402


class AdapterExitStatusTest(unittest.TestCase):
    def _args(self, name: str, binary: str) -> SimpleNamespace:
        return SimpleNamespace(
            resolved_tools={name: binary},
            timeout=180,
            w3goaudit_bin="",
            naly3er_cmd="",
        )

    def test_w3goaudit_nonzero_exit_is_error_even_with_partial_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = root / "Example.sol"
            target.write_text("contract Example {}", encoding="utf-8")
            out = root / "results"
            (out / "raw").mkdir(parents=True)
            matcher = mock.Mock()
            matcher.category_for.return_value = "example"
            adapter = benchmark_adapters.W3GoAuditAdapter(
                root, out, matcher, self._args("w3goaudit", "/bin/w3goaudit")
            )
            case = {
                "id": "example",
                "target": str(target),
                "templates": "templates/example",
            }

            def fake_run(cmd, cwd, stdout, stderr, timeout, env=None):
                stdout.write_text("partial", encoding="utf-8")
                stderr.write_text("failed", encoding="utf-8")
                findings = pathlib.Path(cmd[-1]) / "data" / "findings.json"
                findings.parent.mkdir(parents=True)
                findings.write_text(
                    json.dumps(
                        {
                            "findings": [
                                {
                                    "template_id": "RULE",
                                    "title": "partial finding",
                                    "location": {"file": str(target), "line": 1},
                                }
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
                return {
                    "exit_code": 2,
                    "duration_ms": 1.0,
                    "timed_out": False,
                }

            with mock.patch.object(benchmark_adapters, "run_command", side_effect=fake_run):
                run = adapter.run_case(case, benchmark_adapters.CaseSourceIndex([str(target)], root))

            self.assertEqual(run["status"], "error")
            self.assertIn("w3goaudit exited with 2", run["error"])
            self.assertEqual(run["raw_findings"], 1)

    def test_4naly3er_nonzero_exit_is_error_even_with_partial_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = root / "Example.sol"
            target.write_text("contract Example {}", encoding="utf-8")
            out = root / "results"
            (out / "raw").mkdir(parents=True)
            matcher = mock.Mock()
            matcher.category_for.return_value = "example"
            adapter = benchmark_adapters.Naly3erAdapter(
                root, out, matcher, self._args("4naly3er", "/bin/4naly3er")
            )
            case = {"id": "example", "target": str(target), "templates": ""}

            def fake_run(cmd, cwd, stdout, stderr, timeout, env=None):
                stdout.write_text("", encoding="utf-8")
                stderr.write_text("failed", encoding="utf-8")
                pathlib.Path(cmd[2]).write_text(
                    "# [H-1] Partial issue\nFile: Example.sol\n1: contract Example {}\n",
                    encoding="utf-8",
                )
                return {
                    "exit_code": 3,
                    "duration_ms": 1.0,
                    "timed_out": False,
                }

            with mock.patch.object(benchmark_adapters, "run_command", side_effect=fake_run):
                run = adapter.run_case(case, benchmark_adapters.CaseSourceIndex([str(target)], root))

            self.assertEqual(run["status"], "error")
            self.assertIn("4naly3er exited with 3", run["error"])
            self.assertEqual(run["raw_findings"], 1)

    def test_4naly3er_expands_directory_and_aggregates_fragment_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            targets = root / "contracts"
            targets.mkdir()
            (targets / "B.sol").write_text(
                "contract B {\n    function beta() external {}\n}\n",
                encoding="utf-8",
            )
            (targets / "A.sol").write_text(
                "contract A {\n    function alpha() external {}\n}\n",
                encoding="utf-8",
            )
            out = root / "results"
            (out / "raw").mkdir(parents=True)
            matcher = mock.Mock()
            matcher.category_for.return_value = "example"
            adapter = benchmark_adapters.Naly3erAdapter(
                root, out, matcher, self._args("4naly3er", "/bin/4naly3er")
            )
            case = {"id": "mixed", "target": str(targets), "templates": ""}
            invoked_targets = []

            def fake_run(cmd, cwd, stdout, stderr, timeout, env=None):
                target = pathlib.Path(cmd[1])
                invoked_targets.append(cmd[1])
                stdout.write_text(f"analyzed {target.name}\n", encoding="utf-8")
                stderr.write_text("", encoding="utf-8")
                pathlib.Path(cmd[2]).write_text(
                    f"# [H-1] Issue in {target.stem}\n"
                    f"File: {target.name}\n"
                    "2: finding line\n",
                    encoding="utf-8",
                )
                return {"exit_code": 0, "duration_ms": 1.0, "timed_out": False}

            with mock.patch.object(benchmark_adapters, "run_command", side_effect=fake_run):
                run = adapter.run_case(
                    case,
                    benchmark_adapters.CaseSourceIndex([str(targets)], root),
                )

            self.assertEqual(invoked_targets, ["contracts/A.sol", "contracts/B.sol"])
            self.assertEqual(run["status"], "ok")
            self.assertEqual(run["raw_findings"], 2)
            self.assertEqual(
                [
                    (finding["contract"], finding["function"])
                    for finding in run["findings"]
                ],
                [("A", "alpha"), ("B", "beta")],
            )
            self.assertTrue(
                (out / "raw" / "mixed__contracts_A.sol.4naly3er.md").exists()
            )
            self.assertTrue(
                (out / "raw" / "mixed__contracts_B.sol.4naly3er.md").exists()
            )

    def test_4naly3er_skips_proven_compiler_invalid_fragment_with_successful_sibling(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            targets = root / "contracts"
            targets.mkdir()
            (targets / "Good.sol").write_text("contract Good {}", encoding="utf-8")
            (targets / "Invalid.sol").write_text(
                "contract Invalid {}", encoding="utf-8"
            )
            out = root / "results"
            (out / "raw").mkdir(parents=True)
            matcher = mock.Mock()
            matcher.category_for.return_value = "example"
            adapter = benchmark_adapters.Naly3erAdapter(
                root, out, matcher, self._args("4naly3er", "/bin/4naly3er")
            )
            case = {"id": "mixed", "target": str(targets), "templates": ""}

            def fake_run(cmd, cwd, stdout, stderr, timeout, env=None):
                target = pathlib.Path(cmd[1])
                if target.name == "Good.sol":
                    stdout.write_text("analyzed Good.sol\n", encoding="utf-8")
                    stderr.write_text("", encoding="utf-8")
                    pathlib.Path(cmd[2]).write_text(
                        "# [H-1] Good issue\n"
                        "File: contracts/Good.sol\n"
                        "1: contract Good {}\n",
                        encoding="utf-8",
                    )
                    return {
                        "exit_code": 0,
                        "duration_ms": 1.0,
                        "timed_out": False,
                    }
                stdout.write_text(
                    "Cannot compile AST for contracts/Invalid.sol\n",
                    encoding="utf-8",
                )
                stderr.write_text(
                    "{\n"
                    "  component: 'general',\n"
                    "  errorCode: '8961',\n"
                    "  formattedMessage: 'TypeError: invalid Solidity fragment',\n"
                    "  message: 'invalid Solidity fragment',\n"
                    "  severity: 'error',\n"
                    "  type: 'TypeError'\n"
                    "}\n",
                    encoding="utf-8",
                )
                return {"exit_code": 1, "duration_ms": 1.0, "timed_out": False}

            with mock.patch.object(benchmark_adapters, "run_command", side_effect=fake_run):
                run = adapter.run_case(
                    case,
                    benchmark_adapters.CaseSourceIndex([str(targets)], root),
                )

            self.assertEqual(run["status"], "ok")
            self.assertEqual(run["raw_findings"], 1)
            self.assertIn(
                "1 fragment(s) not analyzable (solc compile error)", run["error"]
            )
            self.assertIn("contracts/Invalid.sol", run["error"])

    def test_4naly3er_runtime_crash_in_one_fragment_marks_aggregate_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            targets = root / "contracts"
            targets.mkdir()
            (targets / "Good.sol").write_text("contract Good {}", encoding="utf-8")
            (targets / "Crash.sol").write_text("contract Crash {}", encoding="utf-8")
            out = root / "results"
            (out / "raw").mkdir(parents=True)
            matcher = mock.Mock()
            matcher.category_for.return_value = "example"
            adapter = benchmark_adapters.Naly3erAdapter(
                root, out, matcher, self._args("4naly3er", "/bin/4naly3er")
            )
            case = {"id": "mixed", "target": str(targets), "templates": ""}

            def fake_run(cmd, cwd, stdout, stderr, timeout, env=None):
                target = pathlib.Path(cmd[1])
                if target.name == "Good.sol":
                    stdout.write_text("analyzed Good.sol\n", encoding="utf-8")
                    stderr.write_text("", encoding="utf-8")
                    pathlib.Path(cmd[2]).write_text(
                        "# [H-1] Good issue\n"
                        "File: contracts/Good.sol\n"
                        "1: contract Good {}\n",
                        encoding="utf-8",
                    )
                    return {
                        "exit_code": 0,
                        "duration_ms": 1.0,
                        "timed_out": False,
                    }
                stdout.write_text(
                    "Cannot compile AST for contracts/Crash.sol\n",
                    encoding="utf-8",
                )
                stderr.write_text(
                    "TypeError: Cannot read properties of undefined\n"
                    "    at analyze (/opt/4naly3er/src/analyze.ts:43:25)\n",
                    encoding="utf-8",
                )
                return {"exit_code": 1, "duration_ms": 1.0, "timed_out": False}

            with mock.patch.object(benchmark_adapters, "run_command", side_effect=fake_run):
                run = adapter.run_case(
                    case,
                    benchmark_adapters.CaseSourceIndex([str(targets)], root),
                )

            self.assertEqual(run["status"], "error")
            self.assertEqual(run["raw_findings"], 1)
            self.assertIn(
                "4naly3er failed without compiler diagnostics", run["error"]
            )

    def test_4naly3er_all_compiler_invalid_fragments_is_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            targets = root / "contracts"
            targets.mkdir()
            (targets / "B.sol").write_text("contract B {}", encoding="utf-8")
            (targets / "A.sol").write_text("contract A {}", encoding="utf-8")
            out = root / "results"
            (out / "raw").mkdir(parents=True)
            adapter = benchmark_adapters.Naly3erAdapter(
                root, out, mock.Mock(), self._args("4naly3er", "/bin/4naly3er")
            )
            case = {"id": "invalid", "target": str(targets), "templates": ""}
            invoked_targets = []

            def fake_run(cmd, cwd, stdout, stderr, timeout, env=None):
                target = pathlib.Path(cmd[1])
                invoked_targets.append(cmd[1])
                stdout.write_text(
                    f"Cannot compile AST for {target.as_posix()}\n",
                    encoding="utf-8",
                )
                stderr.write_text(
                    "{\n"
                    "  component: 'general',\n"
                    "  errorCode: '8936',\n"
                    "  formattedMessage: 'ParserError: invalid Solidity fragment',\n"
                    "  message: 'invalid Solidity fragment',\n"
                    "  severity: 'error',\n"
                    "  type: 'ParserError'\n"
                    "}\n",
                    encoding="utf-8",
                )
                return {"exit_code": 1, "duration_ms": 1.0, "timed_out": False}

            with mock.patch.object(benchmark_adapters, "run_command", side_effect=fake_run):
                run = adapter.run_case(
                    case,
                    benchmark_adapters.CaseSourceIndex([str(targets)], root),
                )

            self.assertEqual(invoked_targets, ["contracts/A.sol", "contracts/B.sol"])
            self.assertEqual(run["status"], "error")
            self.assertEqual(run["raw_findings"], 0)
            self.assertIn(
                "no targets produced output (compiler/tool failure)", run["error"]
            )

    def test_4naly3er_empty_directory_is_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            targets = root / "contracts"
            targets.mkdir()
            out = root / "results"
            (out / "raw").mkdir(parents=True)
            adapter = benchmark_adapters.Naly3erAdapter(
                root, out, mock.Mock(), self._args("4naly3er", "/bin/4naly3er")
            )
            case = {"id": "empty", "target": str(targets), "templates": ""}

            run = adapter.run_case(
                case,
                benchmark_adapters.CaseSourceIndex([str(targets)], root),
            )

            self.assertEqual(run["status"], "error")
            self.assertEqual(run["raw_findings"], 0)
            self.assertIn(
                "no targets produced output (compiler/tool failure)", run["error"]
            )

    def test_slither_nonzero_finding_policy_exit_accepts_successful_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = root / "Example.sol"
            target.write_text("contract Example {}", encoding="utf-8")
            out = root / "results"
            (out / "raw").mkdir(parents=True)
            adapter = benchmark_adapters.SlitherAdapter(
                root,
                out,
                mock.Mock(),
                self._args("slither", "/bin/slither"),
            )
            case = {"id": "example", "target": str(target), "templates": ""}

            def fake_run(cmd, cwd, stdout, stderr, timeout, env=None):
                stdout.write_text("", encoding="utf-8")
                stderr.write_text("findings", encoding="utf-8")
                pathlib.Path(cmd[-1]).write_text(
                    '{"success": true, "results": {"detectors": []}}',
                    encoding="utf-8",
                )
                return {
                    "exit_code": 255,
                    "duration_ms": 1.0,
                    "timed_out": False,
                }

            with mock.patch.object(benchmark_adapters, "run_command", side_effect=fake_run):
                run = adapter.run_case(case, benchmark_adapters.CaseSourceIndex([str(target)], root))

            self.assertEqual(run["status"], "ok")

    def test_slither_success_false_json_is_error_even_with_zero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = root / "Example.sol"
            target.write_text("contract Example {}", encoding="utf-8")
            out = root / "results"
            (out / "raw").mkdir(parents=True)
            adapter = benchmark_adapters.SlitherAdapter(
                root,
                out,
                mock.Mock(),
                self._args("slither", "/bin/slither"),
            )
            case = {"id": "example", "target": str(target), "templates": ""}

            def fake_run(cmd, cwd, stdout, stderr, timeout, env=None):
                stdout.write_text("", encoding="utf-8")
                stderr.write_text("analysis failed", encoding="utf-8")
                pathlib.Path(cmd[-1]).write_text(
                    '{"success": false, "error": "analysis failed", '
                    '"results": {"detectors": []}}',
                    encoding="utf-8",
                )
                return {"exit_code": 0, "duration_ms": 1.0, "timed_out": False}

            with mock.patch.object(benchmark_adapters, "run_command", side_effect=fake_run):
                run = adapter.run_case(case, benchmark_adapters.CaseSourceIndex([str(target)], root))

            self.assertEqual(run["status"], "error")
            self.assertIn("reported unsuccessful analysis", run["error"])

    def test_slither_runtime_crash_in_one_fragment_marks_aggregate_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            targets = root / "contracts"
            targets.mkdir()
            (targets / "Good.sol").write_text("contract Good {}", encoding="utf-8")
            (targets / "Crash.sol").write_text("contract Crash {}", encoding="utf-8")
            out = root / "results"
            (out / "raw").mkdir(parents=True)
            adapter = benchmark_adapters.SlitherAdapter(
                root,
                out,
                mock.Mock(),
                self._args("slither", "/bin/slither"),
            )
            case = {"id": "mixed", "target": str(targets), "templates": ""}

            def fake_run(cmd, cwd, stdout, stderr, timeout, env=None):
                target = pathlib.Path(cmd[1])
                stdout.write_text("", encoding="utf-8")
                if target.name == "Good.sol":
                    stderr.write_text("", encoding="utf-8")
                    pathlib.Path(cmd[-1]).write_text(
                        '{"success": true, "results": {"detectors": []}}',
                        encoding="utf-8",
                    )
                    return {"exit_code": 0, "duration_ms": 1.0, "timed_out": False}
                stderr.write_text(
                    "Traceback (most recent call last):\nRuntimeError: detector crashed\n",
                    encoding="utf-8",
                )
                return {"exit_code": 1, "duration_ms": 1.0, "timed_out": False}

            with mock.patch.object(benchmark_adapters, "run_command", side_effect=fake_run):
                run = adapter.run_case(
                    case,
                    benchmark_adapters.CaseSourceIndex([str(targets)], root),
                )

            self.assertEqual(run["status"], "error")
            self.assertIn("slither failed without compiler diagnostics", run["error"])

    def test_slither_proven_solc_error_remains_non_analyzable_fragment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            targets = root / "contracts"
            targets.mkdir()
            (targets / "Good.sol").write_text("contract Good {}", encoding="utf-8")
            (targets / "Invalid.sol").write_text("contract Invalid {}", encoding="utf-8")
            out = root / "results"
            (out / "raw").mkdir(parents=True)
            adapter = benchmark_adapters.SlitherAdapter(
                root,
                out,
                mock.Mock(),
                self._args("slither", "/bin/slither"),
            )
            case = {"id": "mixed", "target": str(targets), "templates": ""}

            def fake_run(cmd, cwd, stdout, stderr, timeout, env=None):
                target = pathlib.Path(cmd[1])
                stdout.write_text("", encoding="utf-8")
                if target.name == "Good.sol":
                    stderr.write_text("", encoding="utf-8")
                    pathlib.Path(cmd[-1]).write_text(
                        '{"success": true, "results": {"detectors": []}}',
                        encoding="utf-8",
                    )
                    return {"exit_code": 0, "duration_ms": 1.0, "timed_out": False}
                stderr.write_text(
                    "Compilation warnings/errors on Invalid.sol:\n"
                    "Error: Function cannot be declared as view because it modifies state.\n"
                    "Invalid solc compilation\n",
                    encoding="utf-8",
                )
                return {"exit_code": 2, "duration_ms": 1.0, "timed_out": False}

            with mock.patch.object(benchmark_adapters, "run_command", side_effect=fake_run):
                run = adapter.run_case(
                    case,
                    benchmark_adapters.CaseSourceIndex([str(targets)], root),
                )

            self.assertEqual(run["status"], "ok")
            self.assertIn("1 fragment(s) not analyzable (solc compile error)", run["error"])
            self.assertIn("contracts/Invalid.sol", run["error"])

    def test_slither_empty_directory_is_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            targets = root / "contracts"
            targets.mkdir()
            out = root / "results"
            (out / "raw").mkdir(parents=True)
            adapter = benchmark_adapters.SlitherAdapter(
                root,
                out,
                mock.Mock(),
                self._args("slither", "/bin/slither"),
            )
            case = {"id": "empty", "target": str(targets), "templates": ""}

            run = adapter.run_case(
                case,
                benchmark_adapters.CaseSourceIndex([str(targets)], root),
            )

            self.assertEqual(run["status"], "error")
            self.assertEqual(run["raw_findings"], 0)
            self.assertIn(
                "no targets produced output (compiler/tool failure)", run["error"]
            )

    def test_semgrep_exit_one_is_an_accepted_findings_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = root / "Example.sol"
            target.write_text("contract Example {}", encoding="utf-8")
            out = root / "results"
            (out / "raw").mkdir(parents=True)
            args = self._args("semgrep", "/bin/semgrep")
            args.semgrep_config = "config"
            adapter = benchmark_adapters.SemgrepAdapter(root, out, mock.Mock(), args)
            case = {"id": "example", "target": str(target), "templates": ""}

            def fake_run(cmd, cwd, stdout, stderr, timeout, env=None):
                stdout.write_text('{"results": [], "errors": []}', encoding="utf-8")
                stderr.write_text("findings", encoding="utf-8")
                return {
                    "exit_code": 1,
                    "duration_ms": 1.0,
                    "timed_out": False,
                }

            with mock.patch.object(benchmark_adapters, "run_command", side_effect=fake_run):
                run = adapter.run_case(case, benchmark_adapters.CaseSourceIndex([str(target)], root))

            self.assertEqual(run["status"], "ok")



class AdapterCommandTest(unittest.TestCase):
    def _args(self) -> SimpleNamespace:
        return SimpleNamespace(
            resolved_tools={
                "w3goaudit": "/usr/local/bin/w3goaudit",
                "4naly3er": "/usr/local/bin/4naly3er",
            },
            timeout=180,
            w3goaudit_bin="",
            naly3er_cmd="",
        )

    def test_w3goaudit_command_fails_closed_on_invalid_templates(self):
        adapter = benchmark_adapters.W3GoAuditAdapter(
            pathlib.Path("/workspace"),
            pathlib.Path("/workspace/benchmarks/results/test"),
            mock.Mock(),
            self._args(),
        )

        command = adapter.command_for(
            "benchmarks/fixtures/example.sol",
            "benchmarks/templates/example",
            pathlib.Path("/workspace/benchmarks/results/test/raw/w3.out"),
        )

        self.assertNotIn("--ignore-invalid-templates", command)

    def test_4naly3er_command_uses_target_and_report_arguments(self):
        adapter = benchmark_adapters.Naly3erAdapter(
            pathlib.Path("/workspace"),
            pathlib.Path("/workspace/benchmarks/results/test"),
            mock.Mock(),
            self._args(),
        )
        report = pathlib.Path(
            "/workspace/benchmarks/results/test/raw/example.4naly3er.md"
        )

        self.assertEqual(
            adapter.command_for("benchmarks/fixtures/example.sol", report),
            [
                "/usr/local/bin/4naly3er",
                "benchmarks/fixtures/example.sol",
                str(report),
            ],
        )


class FindingsPathTest(unittest.TestCase):
    def test_manifest_declared_findings_path_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            target = out / "machine" / "findings.json"
            target.parent.mkdir(parents=True)
            target.write_text('{"findings": []}', encoding="utf-8")
            manifest = out / "data" / "manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps({"files": {"data": {"findings": "machine/findings.json"}}}),
                encoding="utf-8",
            )

            self.assertEqual(benchmark_adapters.W3GoAuditAdapter._resolve_findings_path(out), target)

    def test_current_layout_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            target = out / "data" / "findings.json"
            target.parent.mkdir(parents=True)
            target.write_text('{"findings": []}', encoding="utf-8")

            self.assertEqual(benchmark_adapters.W3GoAuditAdapter._resolve_findings_path(out), target)


class AdapterRegistryTest(unittest.TestCase):
    def test_registry_contains_supported_adapters(self):
        self.assertEqual(
            set(benchmark_adapters.ADAPTERS),
            {"w3goaudit", "slither", "semgrep", "aderyn", "4naly3er"},
        )


if __name__ == "__main__":
    unittest.main()
