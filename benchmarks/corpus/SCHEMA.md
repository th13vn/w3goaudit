# Corpus Schema

A corpus JSON file is the **answer key** for a benchmark run: it lists the
Solidity files to scan, which bugs each file is known to contain, and how each
tool names those bugs. `run_benchmark.py` loads one corpus per run (selected by
`--suite` or `--corpus`), runs every tool on every case, then scores each tool's
output against the `expected` labels.

See [`registry.json`](registry.json) for the catalog of built-in corpora and the
`--suite` names that map to them.

## Top-level structure

```json
{
  "schema_version": "1.0",
  "name": "Human-readable benchmark name",
  "description": "Short explanation of what this corpus measures.",
  "categories": { "<category-key>": { "title": "...", "aliases": { ... } } },
  "cases":      [ { "id": "...", "target": "...", "expected": [ ... ] } ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | yes | Corpus format version. Currently `"1.0"`. |
| `name` | yes | Human-readable benchmark name (shown in reports). |
| `description` | yes | One or two sentences on what this corpus measures. |
| `categories` | yes | Bug families and the per-tool rule IDs that map to them. |
| `cases` | yes | Solidity files to scan and the bugs expected in each. |

## `categories`

A map from a stable **category key** (e.g. `reentrancy`) to its metadata. The
category key is the shared vocabulary the scorer uses to compare tools — each
tool's native rule IDs are mapped into these keys via `aliases`.

Choose category keys by vulnerability semantics, not detector lineage. Native
rules from different template families that describe the same bug must be
aliases of one canonical category. For example, `SLITHER-SUICIDAL` and
`DECURITY-ACCESSIBLE-SELFDESTRUCT` both belong to `selfdestruct`, while
`SLITHER-CONTROLLED-DELEGATECALL` and
`DECURITY-DELEGATECALL-TO-ARBITRARY-ADDRESS` both belong to
`controlled-delegatecall`. Do not create parallel category keys solely because
the rule IDs use different names.

```json
"categories": {
  "reentrancy": {
    "title": "Reentrancy",
    "aliases": {
      "w3goaudit": ["SLITHER-REENTRANCY-ETH", "SLITHER-REENTRANCY-NO-ETH"],
      "slither":   ["reentrancy-eth", "reentrancy-no-eth"],
      "aderyn":    ["reentrancy"],
      "semgrep":   ["reentrancy"]
    }
  }
}
```

| Field | Required | Meaning |
|---|---|---|
| `title` | yes | Human-readable bug name. |
| `aliases` | yes | Per-tool rule IDs/names that count as this category. Keys are tool names (`w3goaudit`, `slither`, `semgrep`, `4naly3er`, `aderyn`). A tool with no alias entry contributes nothing to this category. |

### Per-tool detector manifests (auto-loaded aliases)

For tools whose detectors are built-in code rather than external rule files
(Slither, 4naly3er), the canonical detector→category map lives in
`benchmarks/config/<tool>/detectors.json`, not in every corpus. `run_benchmark.py`
auto-loads those manifests and folds each entry's `id` and `aliases` in as match
strings for that tool. A corpus then only needs to *name the category*; it does
not have to repeat the tool's detector IDs, and any detector the tool genuinely
emits that the manifest knows is credited rather than silently dropped. Corpus
`aliases` still win over a manifest entry when a corpus deliberately narrows a
category. Semgrep runs real rule files (`config/semgrep-decurity/`), so it has no
manifest and relies on corpus `aliases` + substring matching.

## `cases`

Each case is one logical scan target plus its expected findings.

```json
{
  "id": "slither-detectors",
  "title": "Slither-inspired detector parity fixtures",
  "target": "benchmarks/fixtures/slither-detectors/",
  "templates": "benchmarks/templates/slither-inspired",
  "requires_compilation": false,
  "expected": [
    { "category": "reentrancy", "contract": "Vulnerable_ReentrancyEth", "function": "withdraw" }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Short case name. Used in output/raw file names. |
| `title` | no | Human-readable case title. |
| `target` | one of | A single Solidity file to scan. Use **either** `target` or `targets`. |
| `targets` | one of | A list of Solidity files treated as one logical case. |
| `templates` | yes (w3goaudit) | W3GoAudit template file **or** folder passed via `--template`. A folder runs every YAML inside it. |
| `requires_compilation` | no | `true` if market tools are expected to compile this fixture. Informational today; parser-only fixtures may legitimately show `partial_error` for Slither/Semgrep. |
| `semgrep_config` | no | Path to a Semgrep config dir/file for this case (used by the `decurity` and `competitive` suites to point at the vendored Decurity ruleset). Omit to use the run-wide `--semgrep-config` (default: `benchmarks/config/semgrep-decurity`). |
| `expected` | yes | The bugs that should be found in this case. |

### `expected` entries

| Field | Required | Meaning |
|---|---|---|
| `category` | yes | Must match a key under `categories`. |
| `contract` | yes | Contract name where the bug exists. |
| `function` | yes | Function name where the bug exists. |

The scorer counts a tool's finding as a **true positive** when its mapped
category, contract, and function match an `expected` entry. Findings that map to
a benchmark category but are not in `expected` are **false positives**;
`expected` entries no tool reports are **false negatives**.

## Adding a new corpus

1. Create `benchmarks/corpus/<name>.json` following the structure above.
2. For a named suite, add the mapping to `run_benchmark.SUITES` in
   `../run_benchmark.py`, add the matching entry to
   [`registry.json`](registry.json), and add the suite name to the supported
   suite validation in [`../entrypoint.sh`](../entrypoint.sh).
3. Make sure every `category` used in `cases[].expected` exists under
   `categories`, and that each tool you intend to compare has an `aliases` entry.
4. Run the named suite only through the supported Docker Compose host workflow:

   ```bash
   SUITE=<name> \
     docker compose -f benchmarks/compose.yaml run --rm benchmark
   ```

   The Dockerfile derives and verifies Go directly from the root `go.mod` and
   verifies the reviewed generated-lock hash for the pinned 4naly3er commit.
