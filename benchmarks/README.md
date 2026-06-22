# W3GoAudit Competitive Benchmark

This folder is the benchmark home for W3GoAudit. It answers one question:

> When a Solidity file has known bugs, which tool finds them, which tool misses
> them, and which tool reports extra noise?

It is **self-contained**: the W3GoAudit rule templates, the vulnerable fixtures,
and each comparison tool's rules all live inside `benchmarks/`, so the benchmark
runs from a clean checkout without depending on anything outside this folder.

## Compared tools

| Tool | What it is | Rules used |
|---|---|---|
| `w3goaudit` | this project | `benchmarks/templates/**` (WQL) |
| `slither` | Crytic Slither (built-in Python detectors) | `config/slither/detectors.json` manifest |
| `semgrep` | Semgrep with the **Decurity** Solidity ruleset | `config/semgrep-decurity/*.yaml` (real rules) |
| `4naly3er` | Picodes 4naly3er (built-in TS detectors) | `config/4naly3er/detectors.json` manifest |

Slither and 4naly3er ship their detectors as code, so each has a
`config/<tool>/detectors.json` **manifest** mapping that tool's native detector
IDs/codes onto shared benchmark categories. Semgrep runs external rule files, so
its real rules are vendored verbatim. See [How scoring stays fair](#how-scoring-stays-fair).

## Quick start

```bash
# Default: competitive suite, all four tools, output to results/latest
python3 benchmarks/run_benchmark.py

# Only W3GoAudit (fast; no market tools needed)
python3 benchmarks/run_benchmark.py --tools w3goaudit

# One tool head-to-head
python3 benchmarks/run_benchmark.py --suite slither   --tools w3goaudit,slither
python3 benchmarks/run_benchmark.py --suite decurity  --tools w3goaudit,semgrep
python3 benchmarks/run_benchmark.py --suite 4naly3er  --tools w3goaudit,4naly3er

# Self-contained Docker run with Slither + Semgrep installed in the image
bash benchmarks/run_docker_benchmark.sh
```

Unavailable tools are **skipped**, not fatal — `run_benchmark.py --tools w3goaudit,slither`
still reports W3GoAudit if Slither is missing.

## Suites

| Suite | Corpus | Compares |
|---|---|---|
| `competitive` *(default)* | `corpus/competitive.json` | All tools on the union of every detectable category (72 categories, 3 fixture sets). W3GoAudit runs the full template set on every fixture. |
| `slither` | `corpus/slither-inspired.json` | Slither vs W3GoAudit's Slither port. |
| `decurity` | `corpus/decurity-semgrep-inspired.json` | Decurity Semgrep rules vs W3GoAudit's conversions. |
| `4naly3er` | `corpus/4naly3er-inspired.json` | 4naly3er vs W3GoAudit's 4naly3er port (High/Medium security issues). |

## Folder layout

```text
benchmarks/
  run_benchmark.py            runner (suite -> corpus map in SUITES)
  call_chain.py               call-chain-relaxed scoring helper
  Dockerfile, run_docker_benchmark.sh
  config/                     comparison-tool rules, one folder per tool
    slither/detectors.json        Slither detector manifest (id -> category)
    4naly3er/detectors.json       4naly3er detector manifest (id/aliases -> category)
    semgrep-decurity/*.yaml       vendored Decurity Semgrep rules + README
  templates/                  W3GoAudit WQL rules, grouped by inspiration source
    slither-inspired/  4naly3er-inspired/  decurity-semgrep-inspired/
  fixtures/                   vulnerable Solidity fixtures (one .sol per detector)
    slither-detectors/  4naly3er-detectors/  decurity-semgrep-inspired/
  corpus/                     answer keys
    SCHEMA.md  registry.json  competitive.json  slither-inspired.json
    decurity-semgrep-inspired.json  4naly3er-inspired.json
  results/
    latest/                   default --out (git-ignored, overwritten each run)
    <named-run>/              kept run created with --out benchmarks/results/<name>
```

## What the benchmark does

1. Reads a corpus (the answer key): bug `categories` (with per-tool rule aliases)
   plus `cases` (Solidity fixtures and the bugs expected in each).
2. Runs each tool on each case and **converts every tool's native output into one
   shape**: `case`, `category`, `contract`, `function`, `rule_id`.
3. Scores each tool against the answer key: TP (found), FP (extra noise), FN (missed),
   then precision / detection-rate / F1, overall and per bug type.
4. Writes `results/<out>/benchmark.md` (read this), `benchmark.json`, and raw tool output under `raw/`.

### How scoring stays fair

- **Output conversion never drops a real hit.** Each tool's native IDs are mapped
  to shared categories through (a) the corpus `aliases`, (b) the auto-loaded
  `config/<tool>/detectors.json` manifest, and (c) case-insensitive substring
  matching. So if a tool genuinely reports a bug under any known form of its
  detector id/title, it is credited — it is not penalised for naming.
- **The corpus is scoped to what tools can find.** Every category is detectable by
  at least one compared tool; a tool with no detector for a category legitimately
  records a miss (FN) rather than being unfairly blamed.
- **Same bug, different function = still found.** `call_chain.py` relaxes
  `(contract, function)` equality when two tools attribute the same bug to
  different functions on the same internal-call chain (built once per case from
  `w3goaudit build`). Strict equality is tried first, so exact scores are preserved.

## Reading results

`results/latest/benchmark.md` is the human report.

| Word | Meaning |
|---|---|
| TP | bug existed and the tool found it |
| FP | tool reported something not in the answer key (noise) |
| FN | bug existed but the tool missed it |
| Precision | how clean the findings are (less noise = higher) |
| Detection Rate | how many expected bugs were found (fewer misses = higher) |
| F1 | combined precision + detection-rate score |

## Adding a corpus

1. Create `corpus/<name>.json` (see `corpus/SCHEMA.md`).
2. Add it to `corpus/registry.json` and the `SUITES` map in `run_benchmark.py`.
3. Ensure every `category` used in `cases[].expected` exists under `categories`,
   and that built-in-detector tools have an entry in their
   `config/<tool>/detectors.json` manifest.

> **Next:** the upcoming competitive benchmark on a public dataset and
> real-world exploited contracts (DeFiHackLabs) plugs in as additional fixture
> sets under `fixtures/` + corpora under `corpus/`, with a matching
> `templates/realworld-inspired/` lane added for the W3GoAudit rules.
