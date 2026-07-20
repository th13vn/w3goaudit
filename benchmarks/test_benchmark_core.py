import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

BENCHMARKS = pathlib.Path(__file__).resolve().parent
ROOT = BENCHMARKS.parent
sys.path.insert(0, str(BENCHMARKS))

import benchmark_core
import run_benchmark


class ProcessArtifactTest(unittest.TestCase):
    def test_run_command_streams_stdout_and_stderr_to_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            stdout = base / "stdout.log"
            stderr = base / "stderr.log"
            completed = SimpleNamespace(returncode=0)

            with mock.patch.object(
                benchmark_core.subprocess, "run", return_value=completed
            ) as run:
                result = benchmark_core.run_command(
                    ["scanner", "target.sol"], base, stdout, stderr, 10
                )

            kwargs = run.call_args.kwargs
            self.assertNotIn("capture_output", kwargs)
            self.assertEqual(kwargs["stdout"].name, str(stdout))
            self.assertEqual(kwargs["stderr"].name, str(stderr))
            self.assertEqual(result["exit_code"], 0)

    def test_run_command_appends_timeout_marker_to_streamed_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            stdout = base / "stdout.log"
            stderr = base / "stderr.log"

            with mock.patch.object(
                benchmark_core.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(["scanner"], 10),
            ):
                result = benchmark_core.run_command(
                    ["scanner"], base, stdout, stderr, 10
                )

            self.assertTrue(result["timed_out"])
            self.assertIn("TIMEOUT", stderr.read_text(encoding="utf-8"))

    def test_combine_raw_files_preserves_headers_and_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            first = base / "first.log"
            second = base / "second.log"
            output = base / "combined.log"
            first.write_text("alpha\n", encoding="utf-8")
            second.write_text("beta", encoding="utf-8")

            benchmark_core.combine_raw_files(
                output,
                [("a.sol", first), ("b.sol", second)],
            )

            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "===== a.sol :: first.log =====\nalpha\n\n"
                "===== b.sol :: second.log =====\nbeta\n",
            )


class ToolAvailabilityTest(unittest.TestCase):
    def test_requested_missing_tool_is_fatal(self):
        with mock.patch.object(benchmark_core, "find_executable", return_value=""):
            with self.assertRaisesRegex(
                RuntimeError, "requested tool slither is unavailable"
            ):
                benchmark_core.require_tools(["slither"])

    def test_preparation_failure_is_fatal(self):
        adapter = mock.Mock()
        adapter.available.return_value = (True, "")
        adapter.prepare.side_effect = RuntimeError("broken setup")

        with self.assertRaisesRegex(
            RuntimeError, "failed to prepare requested tool slither: broken setup"
        ):
            benchmark_core.prepare_requested_tool("slither", adapter)


class CorpusCategoryOntologyTest(unittest.TestCase):
    CORPORA = (
        "competitive.json",
        "decurity-semgrep-inspired.json",
    )
    CANONICAL_RULES = {
        "selfdestruct": (
            "SLITHER-SUICIDAL",
            "DECURITY-ACCESSIBLE-SELFDESTRUCT",
        ),
        "controlled-delegatecall": (
            "SLITHER-CONTROLLED-DELEGATECALL",
            "DECURITY-DELEGATECALL-TO-ARBITRARY-ADDRESS",
        ),
    }
    RETIRED_CATEGORIES = {
        "accessible-selfdestruct",
        "delegatecall-to-arbitrary-address",
    }

    @staticmethod
    def _load_corpus(corpus_name):
        return json.loads(
            (BENCHMARKS / "corpus" / corpus_name).read_text(encoding="utf-8")
        )

    def test_synonymous_native_rules_share_canonical_categories(self):
        for corpus_name in self.CORPORA:
            corpus = self._load_corpus(corpus_name)
            matcher = benchmark_core.AliasMatcher(corpus)

            for category, rule_ids in self.CANONICAL_RULES.items():
                for rule_id in rule_ids:
                    with self.subTest(
                        corpus=corpus_name,
                        rule_id=rule_id,
                        canonical_category=category,
                    ):
                        self.assertEqual(
                            matcher.category_for("w3goaudit", rule_id),
                            category,
                        )

    def test_retired_categories_are_absent(self):
        for corpus_name in self.CORPORA:
            with self.subTest(corpus=corpus_name):
                corpus = self._load_corpus(corpus_name)
                self.assertTrue(
                    self.RETIRED_CATEGORIES.isdisjoint(corpus["categories"])
                )
                expected_categories = {
                    expected["category"]
                    for case in corpus["cases"]
                    for expected in case["expected"]
                }
                self.assertTrue(
                    self.RETIRED_CATEGORIES.isdisjoint(expected_categories)
                )


class ContainerOutputTest(unittest.TestCase):
    def test_result_path_inside_root_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "results"
            root.mkdir()

            self.assertEqual(
                benchmark_core.resolve_output_path(root, "named/run"),
                root.resolve() / "named" / "run",
            )

    def test_result_path_must_stay_under_results_root(self):
        root = pathlib.Path("/workspace/benchmarks/results")
        with self.assertRaisesRegex(ValueError, "outside benchmark results root"):
            benchmark_core.resolve_output_path(root, "../../tmp/out")

    def test_existing_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            root = base / "results"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "escape").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "outside benchmark results root"):
                benchmark_core.resolve_output_path(root, "escape/run")

    def test_preflight_failure_does_not_replace_existing_raw_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            corpus = root / "corpus.json"
            corpus.write_text('{"cases": [], "categories": {}}', encoding="utf-8")
            out = root / "results"
            raw = out / "raw"
            raw.mkdir(parents=True)
            marker = raw / "keep.txt"
            marker.write_text("preserve", encoding="utf-8")
            args = SimpleNamespace(
                root=str(root),
                suite="competitive",
                corpus=str(corpus),
                out=str(out),
                tools="w3goaudit",
                timeout=180,
                w3goaudit_bin="/usr/local/bin/w3goaudit",
                config_dir="benchmarks/config",
                semgrep_config="benchmarks/config/semgrep-decurity",
                naly3er_cmd="",
            )

            with (
                mock.patch.dict(
                    os.environ,
                    {"W3GOAUDIT_BENCHMARK_CONTAINER": ""},
                ),
                mock.patch.object(run_benchmark, "parse_args", return_value=args),
                mock.patch.object(
                    run_benchmark,
                    "require_tools",
                    return_value={"w3goaudit": "/usr/local/bin/w3goaudit"},
                ),
                mock.patch.object(
                    run_benchmark,
                    "prepare_requested_tool",
                    side_effect=RuntimeError("preflight failed"),
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "preflight failed"):
                    run_benchmark.main()

            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")


class SourceIndexLexicalSanitizerTest(unittest.TestCase):
    @staticmethod
    def _line_with(source: str, marker: str) -> int:
        return next(
            index
            for index, line in enumerate(source.splitlines(), start=1)
            if marker in line
        )

    def test_strings_and_block_comments_do_not_end_real_ranges(self):
        source = r'''contract Real {
    function target(bool ok) external {
        require(ok, "}");
        string memory singleQuoted = '}';
        string memory escaped = "quote: \" slash: \\ brace: }";
        /* } function FakeInsideComment() external { */
        uint256 findingLine = 1;
    }
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Real.sol"
            path.write_text(source, encoding="utf-8")

            index = benchmark_core.SourceIndex(path)

            self.assertEqual(
                index.lookup(self._line_with(source, "findingLine")),
                ("Real", "target"),
            )
            self.assertNotIn(
                "FakeInsideComment", {name for _, _, name in index.functions}
            )

    def test_multiline_lexical_state_masks_fake_declarations_and_braces(self):
        source = r'''/*
contract Phantom {
    function ghost() external { }
}
*/
contract Real {
    function target() external {
        string memory continued = "escaped quote \" and slash \\
            } function FakeInString() external {";
        uint256 findingLine = 1;
    }
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Real.sol"
            path.write_text(source, encoding="utf-8")

            index = benchmark_core.SourceIndex(path)

            self.assertEqual(
                index.lookup(self._line_with(source, "findingLine")),
                ("Real", "target"),
            )
            self.assertEqual([name for _, _, name in index.contracts], ["Real"])
            self.assertEqual([name for _, _, name in index.functions], ["target"])


class CaseSourceIndexTest(unittest.TestCase):
    @staticmethod
    def _write_source(path: pathlib.Path, contract: str, function: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"contract {contract} {{\n"
            f"    function {function}() external {{}}\n"
            "}\n",
            encoding="utf-8",
        )

    def test_unique_basename_resolves_the_matching_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            contracts = root / "contracts"
            self._write_source(contracts / "Alpha.sol", "Alpha", "alpha")
            self._write_source(contracts / "Beta.sol", "Beta", "beta")

            source = benchmark_core.CaseSourceIndex([str(contracts)], root)

            self.assertEqual(source.lookup(2, "Beta.sol"), ("Beta", "beta"))

    def test_ambiguous_basename_does_not_misattribute(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            left = root / "left" / "Shared.sol"
            right = root / "right" / "Shared.sol"
            self._write_source(left, "Left", "left")
            self._write_source(right, "Right", "right")

            source = benchmark_core.CaseSourceIndex([str(left), str(right)], root)

            self.assertEqual(source.lookup(2, "Shared.sol"), ("", ""))

    def test_unknown_path_in_multi_source_case_does_not_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            first = root / "First.sol"
            second = root / "Second.sol"
            self._write_source(first, "First", "first")
            self._write_source(second, "Second", "second")

            source = benchmark_core.CaseSourceIndex([str(first), str(second)], root)

            self.assertEqual(source.lookup(2, "Missing.sol"), ("", ""))

    def test_exact_relative_and_absolute_paths_beat_ambiguous_basename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            left = root / "left" / "Shared.sol"
            right = root / "right" / "Shared.sol"
            self._write_source(left, "Left", "left")
            self._write_source(right, "Right", "right")

            source = benchmark_core.CaseSourceIndex([str(left), str(right)], root)

            self.assertEqual(
                source.lookup(2, "right/../right/Shared.sol"),
                ("Right", "right"),
            )
            self.assertEqual(
                source.lookup(2, str(left.resolve())),
                ("Left", "left"),
            )

    def test_unknown_path_falls_back_when_case_has_one_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            only = root / "Only.sol"
            self._write_source(only, "Only", "only")

            source = benchmark_core.CaseSourceIndex([str(only)], root)

            self.assertEqual(
                source.lookup(2, "tool-reported-alias.sol"),
                ("Only", "only"),
            )
