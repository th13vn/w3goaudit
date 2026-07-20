# Benchmark Results Store

This directory stores benchmark **results**. The benchmark harness itself
(runner, corpora, fixtures, adapters, Docker files) lives under `scripts/`,
which is **dev-only and git-ignored** — it is not part of a fresh clone or the
published release. The commands below run only where a maintainer has the
harness checked out. Benchmark-dependent Go tests skip automatically when it is
absent.

## Layout

- `yyyy-mm-dd-<commit-slug>.md` — tracked, durable benchmark reports. Each file
  is the `benchmark.md` of one run, named by run date and the short subject of
  the commit it measured (e.g. `2026-07-20-correctness-closure.md`).
- `results/` — Git-ignored scratch directory where runs write their raw output
  folders (`benchmark.md`, `benchmark.json`, per-tool artifacts). Safe to
  delete at any time.

## Producing a result

```bash
go build -o /tmp/w3goaudit ./cmd/w3goaudit
python3 scripts/benchmark/run_benchmark.py --suite competitive --tools w3goaudit \
  --w3goaudit-bin /tmp/w3goaudit --out benchmarks/results/latest
python3 scripts/benchmark/assert_thresholds.py benchmarks/results/latest/benchmark.json
cp benchmarks/results/latest/benchmark.md "benchmarks/$(date +%F)-<commit-slug>.md"
```

The quality gate requires precision >= 0.65, recall >= 0.95, and zero failed
cases. Docker Compose (`scripts/benchmark/compose.yaml`) is needed only for the
multi-tool comparison against Slither/Semgrep/4naly3er.
