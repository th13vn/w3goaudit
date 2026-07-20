# Semgrep — Decurity Solidity rules (vendored)

This folder holds the **real, runnable Semgrep rules** used as the Semgrep
comparison baseline in the benchmark. Unlike Slither and 4naly3er (whose
detectors are built-in code, documented here as `detectors.json` manifests),
Semgrep runs from external YAML rule files, so the actual rules are vendored
verbatim.

| | |
|---|---|
| Source | https://github.com/Decurity/semgrep-smart-contracts |
| Path in source | `security/` |
| Rules vendored | 42 `.yaml` files |
| Used by | `run_benchmark.py` Semgrep adapter (`--semgrep-config benchmarks/config/semgrep-decurity`) and the `decurity` / `competitive` corpora |

Each rule's `id` is what Semgrep emits as `check_id` in its JSON output; the
corpus `categories[].aliases.semgrep` and the benchmark's substring matching map
those onto shared benchmark categories so a finding is credited regardless of
the exact `check_id` form Semgrep prints.

To refresh: re-copy `security/*.yaml` from the upstream repo at a pinned commit
and update the rule count above.
