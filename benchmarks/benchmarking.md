# Benchmarking W3GoAudit

This repository now has a small, reproducible benchmark harness for comparing
W3GoAudit with other Solidity static analyzers.

## Method

The benchmark uses a labeled corpus instead of comparing raw alert totals. Raw
alert counts reward noisy scanners, so the harness normalizes each tool's output
into:

- `case_id`
- vulnerability category
- contract
- function
- source line
- rule id

It then compares unique scoped findings against the labels in
`benchmarks/security-corpus.json` and reports precision, recall, F1, runtime,
raw findings, and skip/error reasons.

The seed corpus intentionally starts with two compiler-valid cases:

- `arbitrary-transferfrom`: 10 expected vulnerable functions across the direct
  access-control fixture and the interprocedural taint fixture
- `reentrancy`: 5 expected vulnerable functions

This keeps peer tools such as Slither on fair ground. Some W3GoAudit-only unit
fixtures intentionally do not pass `solc`; those are useful for template
development, but they should not be mixed into a market-tool benchmark unless
the failure mode is reported separately.

## Run

```bash
python3 benchmarks/run_benchmark.py
```

To allow Solhint via `npx` when it is not globally installed:

```bash
python3 benchmarks/run_benchmark.py --allow-npx
```

Outputs are written to:

- `benchmark-results/latest/benchmark.md`
- `benchmark-results/latest/benchmark.json`
- `benchmark-results/latest/raw/`

To run the full `templates/security/` pack instead of only the intended
template for each case:

```bash
python3 benchmarks/run_benchmark.py \
  --allow-npx \
  --corpus benchmarks/security-full-templates-corpus.json \
  --out benchmark-results/full-templates-latest
```

To benchmark every security template category currently covered by
`test-data/security/`, use the all-bug corpus:

```bash
python3 benchmarks/run_benchmark.py \
  --allow-npx \
  --corpus benchmarks/security-all-bugs-corpus.json \
  --out benchmark-results/latest
```

That corpus intentionally includes parser fixtures that exercise templates which
are not compiler-valid under Solidity 0.8, such as `view` functions that write
state via assembly. W3GoAudit can parse and benchmark them; compiler-dependent
tools may show `partial_error` for those cases.

## Supported Adapters

- `w3goaudit`: builds the local Go CLI unless `--w3goaudit-bin` is provided.
- `slither`: reads Slither detector JSON.
- `aderyn`: runs if the `aderyn` CLI is installed.
- `semgrep`: runs if the `semgrep` CLI is installed; defaults to `p/solidity`.
- `solhint`: runs if `solhint` is installed, or through `npx` with `--allow-npx`.

Unavailable tools are marked as skipped instead of failing the benchmark.

## Extending The Corpus

Add cases to `benchmarks/security-corpus.json`:

```json
{
  "id": "new-case",
  "target": "test-data/security/new-case.sol",
  "templates": "templates/security/new-rule.yaml",
  "requires_compilation": true,
  "expected": [
    {
      "category": "reentrancy",
      "contract": "VulnerableExample",
      "function": "withdraw"
    }
  ]
}
```

A case can also use `targets` when one logical category spans multiple
compiler-valid files:

```json
{
  "id": "merged-case",
  "targets": [
    "test-data/security/case-a.sol",
    "test-data/security/case-b.sol"
  ],
  "templates": "templates/security/rule.yaml",
  "expected": []
}
```

Add category aliases when another tool uses a different rule name for the same
vulnerability class. Only findings mapped to a benchmark category count toward
precision and recall; out-of-scope alerts are still preserved in the raw output.

## Recommended Benchmark Strategy

Use three tiers:

1. Seed fixtures: small labeled contracts like the current corpus. These catch
   regressions and false-positive drift quickly.
2. Compiler-valid synthetic suites: one file per vulnerability class with
   vulnerable, safe, and edge-case variants.
3. Historical exploit regressions: real vulnerable revisions and their patched
   versions. This is the strongest signal for audit usefulness.

Track both detection quality and triage cost. A tool that finds all positives
but floods safe functions should be treated differently from a tool with fewer,
cleaner alerts.
