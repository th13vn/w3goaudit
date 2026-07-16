import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


BENCHMARKS = pathlib.Path(__file__).resolve().parent


YAML_DIRECT_KEY = re.compile(
    r"^(?P<indent> *)(?P<key>"
    r'"(?:[^"\\]|\\.)*"'
    r"|'(?:[^']|'')*'"
    r"|[A-Za-z_][A-Za-z0-9_-]*)\s*:(?P<value>.*)$"
)


def yaml_direct_entries(
    lines: list[str], indent: int
) -> list[tuple[int, str, str]]:
    entries = []
    for index, line in enumerate(lines):
        match = YAML_DIRECT_KEY.fullmatch(line)
        if match is None or len(match.group("indent")) != indent:
            continue
        token = match.group("key")
        if token.startswith('"'):
            key = json.loads(token)
        elif token.startswith("'"):
            key = token[1:-1].replace("''", "'")
        else:
            key = token
        entries.append((index, key, match.group("value").strip()))
    return entries


def yaml_block(lines: list[str], key: str, indent: int) -> list[str]:
    matches = [entry for entry in yaml_direct_entries(lines, indent) if entry[1] == key]
    if len(matches) != 1:
        raise AssertionError(
            f"expected one direct {key!r} block, found {len(matches)}"
        )
    index, _key, value = matches[0]
    if value:
        raise AssertionError(f"expected a block value for direct key {key!r}")

    block = []
    for line in lines[index + 1 :]:
        if line and len(line) - len(line.lstrip()) <= indent:
            break
        block.append(line)
    return block


def yaml_list_items(lines: list[str], key: str, indent: int) -> list[str]:
    prefix = f"{' ' * (indent + 2)}- "
    return [
        line[len(prefix) :]
        for line in yaml_block(lines, key, indent)
        if line.startswith(prefix)
    ]


def yaml_direct_scalar(lines: list[str], key: str, indent: int) -> str:
    values = [
        value
        for _index, entry_key, value in yaml_direct_entries(lines, indent)
        if entry_key == key
    ]
    if len(values) != 1:
        raise AssertionError(
            f"expected one direct {key!r} scalar, found {len(values)}"
        )
    if not values[0]:
        raise AssertionError(f"expected a scalar value for direct key {key!r}")
    return values[0]


class ContainerStaticContractTest(unittest.TestCase):
    def test_compose_has_only_the_results_mount_and_hardening(self):
        compose = (BENCHMARKS / "compose.yaml").read_text(encoding="utf-8")
        lines = compose.splitlines()
        service = yaml_block(lines, "benchmark", 2)

        self.assertEqual(
            yaml_direct_scalar(service, "platform", 4),
            "linux/amd64",
        )
        self.assertEqual(
            yaml_direct_scalar(service, "read_only", 4),
            "true",
        )
        self.assertEqual(
            yaml_list_items(service, "tmpfs", 4),
            ["/tmp:rw,exec,nosuid,nodev,mode=1777,size=4g"],
        )
        self.assertEqual(
            yaml_list_items(service, "volumes", 4),
            ["./results:/workspace/benchmarks/results"],
        )
        build = yaml_block(service, "build", 4)
        self.assertFalse(any(line.strip().startswith("args:") for line in build))

        self.assertNotIn("FOURNALY3ER_LOCK_SHA256", compose)

    def test_dockerfile_exact_pins_and_lock_gate(self):
        dockerfile = (BENCHMARKS / "Dockerfile").read_text(encoding="utf-8")
        for expected in (
            "FROM node:20.20.2-bookworm-slim",
            "ARG GO_LINUX_AMD64_SHA256="
            "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053",
            "ARG SOLC_VERSION=0.8.26",
            "ARG SOLC_SELECT_VERSION=1.2.0",
            "VIRTUAL_ENV=/opt/benchmark-venv",
            "ARG SLITHER_VERSION=0.11.5",
            "ARG SEMGREP_VERSION=1.169.0",
            "ARG YARN_VERSION=1.22.22",
            "ARG FOURNALY3ER_REF=8a9d1ebb7d362bc94f036fa9123d0977c6cb7436",
            "ARG FOURNALY3ER_LOCK_SHA256="
            "5384b83d119c9776fee287b52965b7035de05e27d90758dedace01692f8e81cb",
            'test -n "${FOURNALY3ER_LOCK_SHA256}"',
            'echo "${FOURNALY3ER_LOCK_SHA256}  /opt/4naly3er/yarn.lock" '
            "| sha256sum -c -",
            "--offline --frozen-lockfile",
        ):
            self.assertIn(expected, dockerfile)
        self.assertLess(
            dockerfile.index('test -n "${FOURNALY3ER_LOCK_SHA256}"'),
            dockerfile.index("git init /opt/4naly3er"),
        )
        self.assertNotIn("SOLC_SELECT_DIR", dockerfile)


class ContainerStaticAvailabilityTest(unittest.TestCase):
    def test_static_contract_remains_executable_without_docker(self):
        spec = importlib.util.spec_from_file_location(
            "test_benchmark_container_without_docker",
            pathlib.Path(__file__),
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        with mock.patch("shutil.which", return_value=None):
            spec.loader.exec_module(module)

        method = (
            module.ContainerStaticContractTest
            .test_compose_has_only_the_results_mount_and_hardening
        )
        self.assertFalse(
            getattr(method, "__unittest_skip__", False),
            "the static Compose contract must not depend on Docker availability",
        )

    def test_static_contract_does_not_skip_unsupported_compose_json(self):
        unsupported = subprocess.CompletedProcess(
            args=["docker", "compose"],
            returncode=1,
            stdout="",
            stderr="unknown flag: --format",
        )
        case = ContainerStaticContractTest(
            "test_compose_has_only_the_results_mount_and_hardening"
        )
        with mock.patch("subprocess.run", return_value=unsupported):
            try:
                case.test_compose_has_only_the_results_mount_and_hardening()
            except unittest.SkipTest as exc:
                self.fail(f"static Compose validation skipped: {exc}")


class ContainerScalarUniquenessTest(unittest.TestCase):
    def assert_compose_mutation_rejected(self, original: str, replacement: str):
        compose = (BENCHMARKS / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn(original, compose)
        mutated = compose.replace(original, replacement, 1)

        with tempfile.TemporaryDirectory() as tmp:
            benchmark_dir = pathlib.Path(tmp)
            (benchmark_dir / "compose.yaml").write_text(mutated, encoding="utf-8")
            case = ContainerStaticContractTest(
                "test_compose_has_only_the_results_mount_and_hardening"
            )
            with mock.patch.object(
                sys.modules[__name__],
                "BENCHMARKS",
                benchmark_dir,
            ):
                with self.assertRaises(AssertionError):
                    case.test_compose_has_only_the_results_mount_and_hardening()

    def test_conflicting_duplicate_platform_is_rejected(self):
        self.assert_compose_mutation_rejected(
            "    platform: linux/amd64",
            "    platform: linux/amd64\n    platform: linux/arm64",
        )

    def test_conflicting_duplicate_read_only_is_rejected(self):
        self.assert_compose_mutation_rejected(
            "    read_only: true",
            "    read_only: true\n    read_only: false",
        )

    def test_double_quoted_duplicate_platform_is_rejected(self):
        self.assert_compose_mutation_rejected(
            "    platform: linux/amd64",
            '    platform: linux/amd64\n    "platform": linux/arm64',
        )

    def test_single_quoted_spaced_duplicate_read_only_is_rejected(self):
        self.assert_compose_mutation_rejected(
            "    read_only: true",
            "    read_only: true\n    'read_only' : false",
        )

    def test_unquoted_spaced_duplicate_platform_is_rejected(self):
        self.assert_compose_mutation_rejected(
            "    platform: linux/amd64",
            "    platform: linux/amd64\n    platform : linux/arm64",
        )

    def test_quoted_equivalent_build_block_is_rejected(self):
        self.assert_compose_mutation_rejected(
            "    build:",
            '    build:\n    "build" :',
        )

    def test_nested_scalar_key_does_not_count_as_a_direct_definition(self):
        service = [
            "    platform: linux/amd64",
            "      platform: linux/arm64",
        ]
        self.assertEqual(
            yaml_direct_scalar(service, "platform", 4),
            "linux/amd64",
        )


class ContainerRuntimeContractTest(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("W3GOAUDIT_BENCHMARK_CONTAINER") == "1",
        "benchmark container runtime unavailable",
    )
    def test_runtime_uses_pinned_solc_select_state(self):
        versions = subprocess.run(
            ["solc-select", "versions"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(versions.returncode, 0, versions.stderr)
        self.assertRegex(
            versions.stdout,
            r"(?m)^0\.8\.26 \(current(?:, [^)]+)?\)$",
        )

        compiler = subprocess.run(
            ["solc", "--version"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(compiler.returncode, 0, compiler.stderr)
        version = re.search(
            r"(?m)^Version: (\d+\.\d+\.\d+)(?:\+[^\s]+)?$",
            compiler.stdout,
        )
        self.assertIsNotNone(version, compiler.stdout)
        self.assertEqual(version.group(1), "0.8.26")


if __name__ == "__main__":
    unittest.main()
