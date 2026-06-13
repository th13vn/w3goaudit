# test-data/

Solidity fixtures used by unit tests, integration tests, and the documented
developer workflows. Two top-level groups: **`security/`** holds the general
W3GoAudit-native vulnerability-detection fixtures (paired with
`templates/official/`); **`core/`** holds fixtures that exercise the tool's
core pipeline — parser/builder, WQL engine, and the CLI — rather than security
detection.

| Group | What it holds | Used by |
|---|---|---|
| [`security/`](security/) | General W3GoAudit-native detection fixtures for the official pack in [`../templates/official/`](../templates/official/) — deep single-class fixtures plus one `Vulnerable_*`/`Safe_*` fixture per promoted detector. See [`security/README.md`](security/README.md). | `pkg/engine/interprocedural_taint_test.go`, the documented full-pack scan |
| [`core/`](core/) | Core-pipeline / tool fixtures (not security detection) — see the sub-table below. | builder/reader/engine unit tests, the documented `build` + `engine-features` smoke tests |

### `core/` — pipeline & tool fixtures

| Subdirectory | What it exercises | Used by |
|---|---|---|
| [`core/build-database/`](core/build-database/) | Parser + builder (parsing, inheritance, selectors, call graph, C3 linearization, AST construction). Numbered `01-..` through `10-..`. `10-override-state-order.sol` is an asymmetric Base/Left/Right/Middle/Derived diamond that pins C3 linearization, state-variable storage order, and MRO function-override binding. | `pkg/builder/builder_test.go`, `pkg/reader/reader_test.go`, the documented `w3goaudit build` smoke test |
| [`core/engine-features/`](core/engine-features/) | WQL engine operators (`sequence`, `inside`, semantic groups, `args` + `tainted_from`). Paired with [`../templates/test/`](../templates/test/). Also `type-cast-guards.sol` and the `path-collision/{pkg-a,pkg-b}/tx-origin.sol` pair (same-named files in sibling packages). | `pkg/engine/*_test.go`, the documented `w3goaudit … --template templates/test/` smoke test |
| [`core/extract/`](core/extract/) | CLI `extract` subcommands (entry, inheritance, source, context, bundle, workflow). Realistic multi-bug DeFi vault fixture. | `cmd/w3goaudit/extract_test.go`, `cmd/w3goaudit/extract*.go` examples, `docs/usage.md` |

## Conventions

- **Vulnerable* / Safe*** — every fixture pairs a `Vulnerable…` contract with a
  matching `Safe…` (and sometimes `EdgeCase…`) contract so the same scan can
  surface both true positives and the absence of false positives. Header
  comments explain which detector should/should not fire.
- **Numeric prefixes (`01-`, `02-`, …)** are used where order matters (the
  `core/build-database/` parser sequence) or where the dir is an explicit
  feature matrix (`core/engine-features/`). Security fixtures use bug-class or
  detector-set names instead — order does not matter there.
- No `test-` prefix on fixture filenames — every file under `test-data/` is a
  test fixture by definition; restating it in the name was noise.
