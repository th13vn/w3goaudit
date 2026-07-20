# W3GoAudit Competitive Benchmark

This directory contains the self-contained competitive benchmark for
W3GoAudit, Slither, Semgrep with the vendored Decurity rules, and 4naly3er. The
corpora, Solidity fixtures, detector mappings, W3GoAudit templates, runner, and
threshold gate all live under `benchmarks/`.

## Supported host workflow

Docker Compose is the only supported host entry point. The host does not need
Python, Go, Solidity compilers, or any compared scanner installed; those tools
are pinned in the benchmark image.

```bash
docker compose -f benchmarks/compose.yaml run --rm benchmark
```

The Dockerfile carries the reviewed generated-lock hash for the pinned
4naly3er commit, so the canonical Compose command needs no build argument.

Compose accepts these environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `SUITE` | `competitive` | Corpus suite: `competitive`, `slither`, `decurity`, or `4naly3er`. |
| `TOOLS` | `w3goaudit,slither,semgrep,4naly3er` | Comma-separated requested scanners. |
| `RUN_NAME` | `latest` | Safe single path component created below `benchmarks/results/`. |

Set any non-default values in the environment of the same Compose command.
`RUN_NAME` accepts letters, digits, dots, underscores, and dashes, but not
leading dots or path separators.

## Fail-closed execution

Every requested scanner is resolved and prepared before raw output is
replaced. A missing executable or preparation failure aborts the run; requested
tools are never silently skipped. Container output is canonicalized beneath
`/workspace/benchmarks/results/<RUN_NAME>`, and Compose exposes only the matching
host `benchmarks/results/` bind mount plus an executable `/tmp` tmpfs.

Slither and 4naly3er run directory cases one Solidity fragment at a time. A
fragment that solc rejects is recorded as not analyzable, while compiler-valid
fragments in the same case still produce evidence. Slither requires explicit
solc/compiler-failure diagnostics before treating missing JSON as a compiler
skip. 4naly3er requires both its `Cannot compile AST for` diagnostic and a
structured Solidity compiler error before treating a missing report the same
way. Timeouts, runtime crashes, unexplained exits, and nonzero exits that still
write a report mark the aggregate case as an error. If no fragment produces
output, the requested tool run fails as a compiler/toolchain failure. This
per-fragment reporting is distinct from skipping an unavailable requested tool.

When `w3goaudit` is requested, the entrypoint runs the threshold gate after the
benchmark runner. The gate recomputes metrics from TP/FP/FN and requires:

- precision at least `0.65`;
- detection rate (recall) at least `0.95`;
- zero failed cases.

Any threshold violation exits nonzero.

Project 1 reruns the competitive suite as a no-regression measurement. The
exact 100 percent W3GoAudit precision and recall gate is delivered by the
semantic-hardening project.

## Suites

The active suites are fully owned by `benchmarks/corpus/`; the `SUITES` map in
`run_benchmark.py` and `corpus/registry.json` must remain synchronized.

| Suite | Corpus | Recommended tools |
|---|---|---|
| `competitive` | `corpus/competitive.json` | all four tools |
| `slither` | `corpus/slither-inspired.json` | `w3goaudit,slither` |
| `decurity` | `corpus/decurity-semgrep-inspired.json` | `w3goaudit,semgrep` |
| `4naly3er` | `corpus/4naly3er-inspired.json` | `w3goaudit,4naly3er` |

Each corpus is the answer key: it identifies fixtures, expected bug categories,
contracts and functions, and per-tool aliases. `corpus/SCHEMA.md` documents the
format, and `corpus/registry.json` catalogs the built-in suites.

## Compared tools and pinned image inputs

| Tool/input | Version or source |
|---|---|
| Base image / Node | `node:20.20.2-bookworm-slim` |
| Go | version from root `go.mod` (`1.26.5`), Linux AMD64 archive SHA-256 pinned in the Dockerfile |
| solc-select / solc | `1.2.0` / `0.8.26` |
| Slither | `0.11.5` |
| Semgrep | `1.169.0` with `config/semgrep-decurity/*.yaml` |
| Yarn | `1.22.22` |
| 4naly3er | commit `8a9d1ebb7d362bc94f036fa9123d0977c6cb7436`; generated `yarn.lock` SHA-256 `5384b83d119c9776fee287b52965b7035de05e27d90758dedace01692f8e81cb` |
| W3GoAudit | built from the current checkout with benchmark templates under `templates/` |

Slither and 4naly3er implement detectors in code, so
`config/<tool>/detectors.json` maps their native IDs to shared benchmark
categories. Semgrep uses the vendored Decurity YAML rules directly.

## Results

The host receives each run under `benchmarks/results/<RUN_NAME>/`:

```text
benchmark.md       human-readable comparison
benchmark.json     machine-readable report and metrics
raw/               per-tool stdout, stderr, and native artifacts
```

All contents beneath `benchmarks/results/` are generated and ignored by Git;
only `.gitkeep` preserves the empty directory in a clean checkout. Both the
default `latest` run and every named run may be overwritten or removed without
changing repository state.

## Scoring model

Each tool's native findings are normalized to `case`, `category`, `contract`,
`function`, and `rule_id`. The scorer compares those findings with the corpus
answer key:

| Metric | Meaning |
|---|---|
| TP | Expected bug found. |
| FP | Benchmark-category finding absent from the answer key. |
| FN | Expected bug missed. |
| Precision | `TP / (TP + FP)`. |
| Detection rate | `TP / (TP + FN)`. |
| F1 | Harmonic mean of precision and detection rate. |

Alias mappings credit equivalent native detector names. Semantically
synonymous detector families share one canonical cross-tool category even when
their native rule IDs come from different template packs. For example,
`SLITHER-SUICIDAL` and `DECURITY-ACCESSIBLE-SELFDESTRUCT` both map to
`selfdestruct`; this category means any unauthenticated reachable destruction,
regardless of whether the beneficiary is fixed or caller-controlled. Meanwhile,
`SLITHER-CONTROLLED-DELEGATECALL` and
`DECURITY-DELEGATECALL-TO-ARBITRARY-ADDRESS` both map to
`controlled-delegatecall`. `call_chain.py` also relaxes function equality when
two tools attribute the same category in the same contract to functions on one
internal call chain; exact matches are tried first.

## Harness modules

The Python harness is split by responsibility while keeping scanner and corpus
case execution sequential:

| Module | Responsibility |
|---|---|
| `run_benchmark.py` | CLI and sequential orchestration. |
| `benchmark_core.py` | Paths, source indexes, process I/O, aliases, and manifests. |
| `benchmark_adapters.py` | Scanner commands and native-output normalization. |
| `benchmark_scoring.py` | Exact/call-chain-relaxed matching and metrics. |
| `benchmark_reporting.py` | `benchmark.md` rendering. |
| `call_chain.py` | Internal-call reachability helper. |
| `assert_thresholds.py` | Release-quality threshold gate. |

`benchmark_core.SourceIndex` derives fallback contract/function labels from one
length- and newline-preserving Solidity lexical sanitizer. Line comments,
block comments, single-quoted strings, double-quoted strings, and escaped
quotes/backslashes are masked before both declaration regexes and brace
counting, so quoted braces and fake declarations cannot corrupt Semgrep or
4naly3er attribution.

Maintainers can exercise the host-independent Python contracts directly:

```bash
python3 -m compileall -q benchmarks
python3 -m unittest discover -s benchmarks -p 'test_*.py' -v
```

These commands verify the harness without documenting an alternative benchmark
entry point. The canonical four-tool command remains:

```bash
docker compose -f benchmarks/compose.yaml run --rm benchmark
```

## Layout

```text
benchmarks/
  Dockerfile, compose.yaml, entrypoint.sh
  run_benchmark.py, assert_thresholds.py, call_chain.py
  config/       comparison-tool detector mappings and vendored rules
  templates/    W3GoAudit WQL benchmark templates
  fixtures/     vulnerable and safe Solidity fragments
  corpus/       active answer keys, schema, and registry
  results/      ignored host output; only .gitkeep is tracked
```

When adding a suite, add its corpus beneath `corpus/`, register it in
`corpus/registry.json`, add the same mapping to `SUITES`, and verify every
referenced target, template, and category exists.
