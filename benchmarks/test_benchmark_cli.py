import os
import pathlib
import re
import subprocess
import tempfile
import unittest


BENCHMARKS = pathlib.Path(__file__).resolve().parent
ROOT = BENCHMARKS.parent


def benchmark_markdown_files() -> list[pathlib.Path]:
    return sorted(
        path
        for path in BENCHMARKS.rglob("*.md")
        if "results" not in path.relative_to(BENCHMARKS).parts
    )


class StaticScanBoundaryTest(unittest.TestCase):
    def test_generated_results_are_not_static_documentation_inputs(self):
        paths = benchmark_markdown_files()
        self.assertTrue(paths)
        self.assertTrue(
            all("results" not in path.relative_to(BENCHMARKS).parts for path in paths)
        )


class FixtureContractTest(unittest.TestCase):
    def test_public_transfer_fee_stub_has_effect_free_statement_ast(self):
        fixture = (
            BENCHMARKS
            / "fixtures"
            / "decurity-semgrep-inspired"
            / "public-transfer-fees-supporting-tax-tokens.sol"
        )
        source = fixture.read_text(encoding="utf-8")
        signature = re.search(
            r"function\s+_transferFeesSupportingTaxTokens\s*\("
            r"\s*address\s+from\s*,\s*address\s+to\s*,"
            r"\s*uint256\s+amount\s*\)\s*external\s*\{",
            source,
        )
        self.assertIsNotNone(signature, "benchmark target function was renamed")

        open_brace = signature.end() - 1
        depth = 0
        close_brace = None
        for offset, char in enumerate(source[open_brace:], start=open_brace):
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    close_brace = offset
                    break
        self.assertIsNotNone(close_brace, "target function body is unbalanced")
        body = source[open_brace + 1 : close_brace]

        self.assertEqual(
            body.strip(),
            "bytes32 ignored = keccak256(abi.encode(from, to, amount));",
        )
        for forbidden in ("if", "require", "return"):
            with self.subTest(forbidden=forbidden):
                self.assertNotRegex(body, rf"\b{forbidden}\b")
        for parameter in ("from", "to", "amount"):
            with self.subTest(parameter=parameter):
                self.assertRegex(body, rf"\b{parameter}\b")


class ShellContractTest(unittest.TestCase):
    def test_entrypoint_dispatches_threshold_only_for_w3goaudit(self):
        entrypoint = BENCHMARKS / "entrypoint.sh"
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            bin_dir = base / "bin"
            bin_dir.mkdir()
            fake_python = bin_dir / "python3"
            fake_python.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$ENTRYPOINT_CALL_LOG"\n',
                encoding="utf-8",
            )
            fake_python.chmod(0o755)

            for tools, expected_calls in (("w3goaudit", 2), ("slither", 1)):
                with self.subTest(tools=tools):
                    log = base / f"{tools}.log"
                    env = os.environ.copy()
                    env.update(
                        {
                            "PATH": f"{bin_dir}:/usr/bin:/bin",
                            "HOME": str(base / "home"),
                            "XDG_CACHE_HOME": str(base / "cache"),
                            "ENTRYPOINT_CALL_LOG": str(log),
                            "SUITE": "competitive",
                            "TOOLS": tools,
                            "RUN_NAME": "review",
                        }
                    )
                    subprocess.run(
                        ["/bin/sh", str(entrypoint)],
                        cwd=ROOT,
                        env=env,
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    calls = log.read_text(encoding="utf-8").splitlines()
                    self.assertEqual(len(calls), expected_calls)
                    self.assertIn("benchmarks/run_benchmark.py", calls[0])
                    if tools == "w3goaudit":
                        self.assertEqual(
                            calls[1],
                            "benchmarks/assert_thresholds.py "
                            "/workspace/benchmarks/results/review/benchmark.json",
                        )

    def test_4naly3er_wrapper_declares_file_and_directory_argv_contract(self):
        script = (BENCHMARKS / "4naly3er-wrapper.sh").read_text(encoding="utf-8")
        self.assertIn('target="$(realpath "$1")"', script)
        self.assertIn('if [ -d "${target}" ]; then', script)
        self.assertIn('set -- "${base_path}"', script)
        self.assertIn('basename "${target}" > "${scope_file}"', script)
        self.assertIn('set -- "${base_path}" "${scope_file}"', script)
        self.assertIn('cd "${workdir}"', script)
        self.assertIn(
            '/opt/4naly3er/node_modules/.bin/ts-node '
            '/opt/4naly3er/src/index.ts "$@"',
            script,
        )

    def test_compose_is_the_only_supported_host_workflow(self):
        for stale in (
            "benchmarking.md",
            "run_docker_benchmark.sh",
            "security-corpus.json",
            "security-full-templates-corpus.json",
            "security-all-bugs-corpus.json",
        ):
            self.assertFalse((BENCHMARKS / stale).exists(), stale)

        readme = (BENCHMARKS / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "docker compose -f benchmarks/compose.yaml run --rm benchmark",
            readme,
        )
        self.assertNotIn("FOURNALY3ER_LOCK_SHA256", readme)
        self.assertNotIn("python3 benchmarks/run_benchmark.py", readme)
        self.assertNotIn("run_docker_benchmark.sh", readme)

        self.assertTrue((BENCHMARKS / "results" / ".gitkeep").is_file())
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("benchmarks/results/*", gitignore)
        self.assertIn("!benchmarks/results/.gitkeep", gitignore)

        forbidden = {
            "direct host Python runner": re.compile(
                r"^\s*(?:\$\s+)?python3\s+benchmarks/run_benchmark\.py\b"
            ),
            "direct host runner prose": re.compile(
                r"\brun\s+(?:it|the\s+benchmark)\s+directly\b.*"
                r"(?:--corpus|--suite|run_benchmark\.py)",
                re.IGNORECASE,
            ),
            "host Python runner prose": re.compile(
                r"\b(?:run|invoke|execute)\b.*\b"
                r"(?:python3?|run_benchmark\.py)\b.*\b(?:directly|host)\b",
                re.IGNORECASE,
            ),
            "direct host W3GoAudit benchmark": re.compile(
                r"^\s*(?:\$\s+)?w3goaudit\s+benchmarks/"
            ),
            "deleted benchmark wrapper": re.compile(r"run_docker_benchmark\.sh"),
            "deleted benchmark guide": re.compile(r"benchmarking\.md"),
        }
        offenders = []
        for markdown in benchmark_markdown_files():
            for line_number, line in enumerate(
                markdown.read_text(encoding="utf-8").splitlines(), start=1
            ):
                for label, pattern in forbidden.items():
                    if pattern.search(line):
                        offenders.append(
                            f"{markdown.relative_to(ROOT)}:{line_number}: {label}"
                        )
        self.assertEqual(offenders, [])

        runner = (BENCHMARKS / "run_benchmark.py").read_text(encoding="utf-8")
        self.assertNotIn("was skipped", runner)
        self.assertNotIn("| skipped |", runner)


if __name__ == "__main__":
    unittest.main()
