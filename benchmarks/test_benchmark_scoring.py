import itertools
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest
from types import SimpleNamespace
from unittest import mock


BENCHMARKS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(BENCHMARKS))

import benchmark_reporting  # noqa: E402
import benchmark_scoring  # noqa: E402
import run_benchmark  # noqa: E402


class ScoringKeyTest(unittest.TestCase):
    def test_expected_and_finding_keys_normalize_function_signatures(self):
        corpus = {
            "cases": [
                {
                    "id": "case-a",
                    "expected": [
                        {
                            "category": "access-control",
                            "contract": "Vault",
                            "function": "deposit(uint256)",
                        }
                    ],
                }
            ]
        }
        finding = {
            "case_id": "case-a",
            "category": "access-control",
            "contract": "Vault",
            "function": "deposit(address)",
        }

        key = ("case-a", "access-control", "Vault", "deposit")
        self.assertEqual(benchmark_scoring.expected_keys(corpus), {key})
        self.assertEqual(benchmark_scoring.finding_key(finding), key)
        self.assertEqual(
            benchmark_scoring.key_to_dict(key),
            {
                "case_id": "case-a",
                "category": "access-control",
                "contract": "Vault",
                "function": "deposit",
            },
        )


class MetricBlockTest(unittest.TestCase):
    def test_metric_block_preserves_four_decimal_rounding(self):
        self.assertEqual(
            benchmark_scoring.metric_block(2, 1, 1),
            {
                "tp": 2,
                "fp": 1,
                "fn": 1,
                "precision": 0.6667,
                "detection_rate": 0.6667,
                "f1": 0.6667,
            },
        )

    def test_metric_block_uses_zero_for_empty_denominators(self):
        self.assertEqual(
            benchmark_scoring.metric_block(0, 0, 0),
            {
                "tp": 0,
                "fp": 0,
                "fn": 0,
                "precision": 0.0,
                "detection_rate": 0.0,
                "f1": 0.0,
            },
        )


class ToolEvaluationTest(unittest.TestCase):
    def setUp(self):
        self.corpus = {
            "categories": {"cat-b": {}, "cat-a": {}},
            "cases": [
                {
                    "id": "case-a",
                    "expected": [
                        {
                            "category": "cat-a",
                            "contract": "Vault",
                            "function": "deposit(uint256)",
                        },
                        {
                            "category": "cat-b",
                            "contract": "Vault",
                            "function": "withdraw",
                        },
                    ],
                }
            ],
        }

    @staticmethod
    def _run(findings):
        return {
            "status": "ok",
            "duration_ms": 1.235,
            "raw_findings": 3,
            "scoped_findings": 3,
            "findings": findings,
        }

    def test_exact_scoring_preserves_metrics_shape_and_order(self):
        runs = [
            self._run(
                [
                    {
                        "case_id": "case-a",
                        "category": "cat-a",
                        "contract": "Vault",
                        "function": "deposit(address)",
                    },
                    {
                        "case_id": "case-a",
                        "category": "cat-a",
                        "contract": "Vault",
                        "function": "deposit(address)",
                    },
                    {
                        "case_id": "case-a",
                        "category": "cat-b",
                        "contract": "Vault",
                        "function": "other",
                    },
                ]
            )
        ]

        result = benchmark_scoring.evaluate_tool("scanner", runs, self.corpus)

        self.assertEqual(result["tool"], "scanner")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["cases"], 1)
        self.assertEqual(result["failed_cases"], 0)
        self.assertEqual(result["duration_ms"], 1.24)
        self.assertEqual(result["raw_findings"], 3)
        self.assertEqual(result["scoped_occurrences"], 3)
        self.assertEqual(result["unique_scoped_findings"], 2)
        self.assertEqual(
            {key: result[key] for key in ("tp", "fp", "fn")},
            {"tp": 1, "fp": 1, "fn": 1},
        )
        self.assertEqual(list(result["by_category"]), ["cat-a", "cat-b"])
        self.assertEqual(
            result["true_positives"],
            [
                {
                    "case_id": "case-a",
                    "category": "cat-a",
                    "contract": "Vault",
                    "function": "deposit",
                }
            ],
        )
        self.assertEqual(result["false_positives"][0]["function"], "other")
        self.assertEqual(result["false_negatives"][0]["function"], "withdraw")

    def test_relaxed_scoring_credits_functions_on_the_same_call_chain(self):
        corpus = {
            "categories": {"reentrancy": {}},
            "cases": [
                {
                    "id": "case-a",
                    "expected": [
                        {
                            "category": "reentrancy",
                            "contract": "Vault",
                            "function": "entry",
                        }
                    ],
                }
            ],
        }
        runs = [
            self._run(
                [
                    {
                        "case_id": "case-a",
                        "category": "reentrancy",
                        "contract": "Vault",
                        "function": "internal",
                    }
                ]
            )
        ]

        strict = benchmark_scoring.evaluate_tool("scanner", runs, corpus)
        relaxed = benchmark_scoring.evaluate_tool(
            "scanner",
            runs,
            corpus,
            {"case-a": {"Vault": {"entry": {"internal"}}}},
        )

        self.assertEqual((strict["tp"], strict["fp"], strict["fn"]), (0, 1, 1))
        self.assertEqual((relaxed["tp"], relaxed["fp"], relaxed["fn"]), (1, 0, 0))


class RelaxedMatchingTest(unittest.TestCase):
    def setUp(self):
        self.actual = (
            ("case-a", "category", "Vault", "a"),
            ("case-a", "category", "Vault", "b"),
        )
        self.expected = (
            ("case-a", "category", "Vault", "x"),
            ("case-a", "category", "Vault", "y"),
        )
        self.chains = {
            "case-a": {
                "Vault": {
                    "a": {"x", "y"},
                    "b": {"x"},
                }
            }
        }
        self.maximum = (list(self.expected), [], [])

    def test_ambiguous_relaxed_graph_uses_maximum_cardinality_matching(self):
        result = benchmark_scoring.call_chain.match_relaxed(
            self.actual,
            self.expected,
            self.chains,
        )

        self.assertEqual(result, self.maximum)

    def test_relaxed_matching_is_stable_across_input_permutations(self):
        results = {
            tuple(
                tuple(part)
                for part in benchmark_scoring.call_chain.match_relaxed(
                    actual,
                    expected,
                    self.chains,
                )
            )
            for actual in itertools.permutations(self.actual)
            for expected in itertools.permutations(self.expected)
        }

        self.assertEqual(
            results,
            {tuple(tuple(part) for part in self.maximum)},
        )

    def test_relaxed_matching_is_stable_across_python_hash_seeds(self):
        script = """
import json
from call_chain import match_relaxed

actual = {
    ("case-a", "category", "Vault", "a"),
    ("case-a", "category", "Vault", "b"),
}
expected = {
    ("case-a", "category", "Vault", "x"),
    ("case-a", "category", "Vault", "y"),
}
chains = {
    "case-a": {
        "Vault": {
            "a": {"x", "y"},
            "b": {"x"},
        }
    }
}
print(json.dumps(match_relaxed(actual, expected, chains)))
"""
        outputs = []
        for seed in ("1", "2", "3"):
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=BENCHMARKS,
                env={**os.environ, "PYTHONHASHSEED": seed},
                check=True,
                capture_output=True,
                text=True,
            )
            outputs.append(json.loads(completed.stdout))

        expected = [[list(key) for key in self.expected], [], []]
        self.assertEqual(outputs, [expected, expected, expected])


class ChainGraphPreparationTest(unittest.TestCase):
    def test_installed_helper_builds_graphs_when_w3goaudit_is_not_selected(self):
        cases = [{"id": "case-a", "target": "fixture.sol"}]
        graph = {"Vault": {"entry": {"internal"}}}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            benchmark_scoring.call_chain,
            "build_case_database",
            return_value=pathlib.Path(tmp) / "case-a.json",
        ) as build, mock.patch.object(
            benchmark_scoring.call_chain,
            "load_case_chain_db",
            return_value=graph,
        ):
            result = benchmark_scoring.build_chain_graphs(
                cases,
                pathlib.Path(tmp),
                pathlib.Path("/usr/local/bin/w3goaudit"),
                pathlib.Path(tmp) / "graphs",
            )

        self.assertEqual(result, {"case-a": graph})
        build.assert_called_once()

    def test_missing_helper_preserves_strict_scoring_fallback(self):
        with mock.patch.object(
            benchmark_scoring.call_chain, "build_case_database"
        ) as build:
            result = benchmark_scoring.build_chain_graphs(
                [{"id": "case-a", "target": "fixture.sol"}],
                pathlib.Path("/repo"),
                None,
                pathlib.Path("/tmp/graphs"),
            )

        self.assertEqual(result, {})
        build.assert_not_called()

    def test_main_builds_shared_chains_when_w3goaudit_is_not_selected(self):
        graph = {"case-a": {"Vault": {"entry": {"internal"}}}}

        class FakeAdapter:
            def __init__(self, root, out_dir, matcher, args):
                self.binary = args.resolved_tools["slither"]

            def available(self):
                return True, ""

            def prepare(self):
                return None

            def version(self):
                return "test"

            def run_case(self, case, source):
                return {
                    "tool": "slither",
                    "case_id": case["id"],
                    "status": "ok",
                    "exit_code": 0,
                    "duration_ms": 1.0,
                    "raw_findings": 0,
                    "scoped_findings": 0,
                    "findings": [],
                    "error": "",
                }

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = root / "fixture.sol"
            target.write_text("contract Vault {}", encoding="utf-8")
            corpus = root / "corpus.json"
            corpus.write_text(
                '{"name":"fixed","categories":{},"cases":['
                '{"id":"case-a","target":"fixture.sol","expected":[]}]}',
                encoding="utf-8",
            )
            out = root / "results"
            args = SimpleNamespace(
                root=str(root),
                suite="competitive",
                corpus=str(corpus),
                out=str(out),
                tools="slither",
                timeout=180,
                w3goaudit_bin="",
                config_dir="benchmarks/config",
                semgrep_config="benchmarks/config/semgrep-decurity",
                naly3er_cmd="",
            )
            metric = {
                "precision": 0.0,
                "detection_rate": 0.0,
                "f1": 0.0,
                "raw_findings": 0,
                "unique_scoped_findings": 0,
            }

            with (
                mock.patch.dict(
                    os.environ,
                    {"W3GOAUDIT_BENCHMARK_CONTAINER": ""},
                ),
                mock.patch.object(run_benchmark, "parse_args", return_value=args),
                mock.patch.object(
                    run_benchmark,
                    "require_tools",
                    return_value={"slither": "/usr/local/bin/slither"},
                ),
                mock.patch.object(
                    run_benchmark,
                    "ADAPTERS",
                    {"slither": FakeAdapter},
                ),
                mock.patch.object(
                    run_benchmark,
                    "find_executable",
                    return_value="/usr/local/bin/w3goaudit",
                ) as discover,
                mock.patch.object(
                    run_benchmark,
                    "build_chain_graphs",
                    return_value=graph,
                    create=True,
                ) as build,
                mock.patch.object(
                    run_benchmark,
                    "evaluate_tool",
                    return_value=metric,
                ) as evaluate,
                mock.patch.object(run_benchmark, "write_markdown"),
                mock.patch("builtins.print"),
            ):
                self.assertEqual(run_benchmark.main(), 0)

            discover.assert_called_once_with("w3goaudit")
            build.assert_called_once_with(
                [{"id": "case-a", "target": "fixture.sol", "expected": []}],
                root.resolve(),
                pathlib.Path("/usr/local/bin/w3goaudit"),
                out / "raw" / ".callgraphs",
            )
            self.assertIs(evaluate.call_args.args[3], graph)


class MarkdownReportingTest(unittest.TestCase):
    def test_markdown_matches_the_pre_extraction_baseline_exactly(self):
        report = {
            "generated_at": "2026-07-16T00:00:00+00:00",
            "corpus": {
                "name": "Fixed Corpus",
                "path": "benchmarks/corpus/fixed.json",
                "cases": [
                    {
                        "id": "case-a",
                        "expected": [
                            {
                                "category": "cat-a",
                                "contract": "Vault",
                                "function": "entry",
                            },
                            {
                                "category": "cat-b",
                                "contract": "Vault",
                                "function": "withdraw",
                            },
                        ],
                    }
                ],
                "categories": {"cat-a": {}, "cat-b": {}},
            },
            "tools": {
                "scanner": {"status": "ok", "reason": "", "version": "1.0"}
            },
            "metrics": {
                "scanner": {
                    "status": "partial_error",
                    "tp": 1,
                    "fp": 1,
                    "fn": 1,
                    "precision": 0.5,
                    "detection_rate": 0.5,
                    "f1": 0.5,
                    "by_category": {
                        "cat-a": {
                            "tp": 1,
                            "fp": 0,
                            "fn": 0,
                            "precision": 1.0,
                            "detection_rate": 1.0,
                            "f1": 1.0,
                        },
                        "cat-b": {
                            "tp": 0,
                            "fp": 1,
                            "fn": 1,
                            "precision": 0.0,
                            "detection_rate": 0.0,
                            "f1": 0.0,
                        },
                    },
                    "false_negatives": [
                        {
                            "case_id": "case-a",
                            "category": "cat-b",
                            "contract": "Vault",
                            "function": "withdraw",
                        }
                    ],
                    "false_positives": [
                        {
                            "case_id": "case-a",
                            "category": "cat-b",
                            "contract": "Vault",
                            "function": "other",
                        }
                    ],
                }
            },
            "runs": [
                {
                    "tool": "scanner",
                    "case_id": "case-a",
                    "status": "error",
                    "exit_code": 2,
                    "duration_ms": 12.34,
                    "raw_findings": 2,
                    "scoped_findings": 2,
                    "error": "bad | output\nsecond line",
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "benchmark.md"
            benchmark_reporting.write_markdown(report, path)
            output_folder = path.parent
            expected = textwrap.dedent(
                f"""\
                # Benchmark Results

                - Generated: `2026-07-16T00:00:00+00:00`
                - Corpus: `Fixed Corpus`
                - Corpus file: `benchmarks/corpus/fixed.json`
                - Cases: `1`
                - Expected bugs: `2`
                - Bug categories: `2`
                - Output folder: `{output_folder}`

                ## What This Benchmark Does

                It runs each tool on Solidity files with known bugs, compares tool findings with the corpus answer key, then reports:

                | Result | Meaning |
                |---|---|
                | Found Bugs | Expected bugs the tool found. This is TP. |
                | Extra Noise | Findings not listed in the answer key. This is FP. |
                | Missed Bugs | Expected bugs the tool did not find. This is FN. |
                | Precision | Cleanliness. Higher means fewer extra findings. |
                | Detection Rate | Coverage. Higher means fewer missed bugs. |
                | F1 | One combined score for precision and detection rate. |

                ## Plain English Result

                - `scanner` ran with errors: found `1/2` expected bugs, missed `1`, and produced `1` extra findings. Precision `50.00%`, detection rate `50.00%`, F1 `50.00%`. Some cases failed for this tool, so compare it carefully.

                ## Scoreboard

                | Tool | Status | Found Bugs | Extra Noise | Missed Bugs | Precision | Detection Rate | F1 |
                |---|---|---:|---:|---:|---:|---:|---:|
                | scanner | ran with errors | 1 | 1 | 1 | 50.00% | 50.00% | 50.00% |

                ## By Bug Type

                | Tool | Bug Type | Found | Noise | Missed | Precision | Detection Rate | F1 |
                |---|---|---:|---:|---:|---:|---:|---:|
                | scanner | cat-a | 1 | 0 | 0 | 100.00% | 100.00% | 100.00% |
                | scanner | cat-b | 0 | 1 | 1 | 0.00% | 0.00% | 0.00% |

                ## Missed Bugs

                - `scanner` missed `1` expected bugs:
                  - `case-a` `cat-b` `Vault.withdraw()`

                ## Extra Findings

                These are benchmark-category findings that were not in the corpus answer key. They are noise for scoring, but some may still be real bugs if the answer key is incomplete.

                - `scanner` produced `1` extra findings:
                  - `case-a` `cat-b` `Vault.other()`

                ## Files Created

                | Path | What It Contains |
                |---|---|
                | `{path}` | This human-readable report. |
                | `{path.with_name('benchmark.json')}` | The same result as JSON for scripts or dashboards. |
                | `{output_folder / 'raw'}/` | Raw output from each tool and case, useful when debugging a failed run. |

                ## Run Details

                Use this section when a tool failed or returned strange results.

                | Tool | Case | Status | Exit | Runtime ms | Raw | Scoped | Error |
                |---|---|---:|---:|---:|---:|---:|---|
                | scanner | case-a | failed | 2 | 12.34 | 2 | 2 | bad \\| output second line |
                """
            )

            self.assertEqual(path.read_text(encoding="utf-8"), expected)


if __name__ == "__main__":
    unittest.main()
