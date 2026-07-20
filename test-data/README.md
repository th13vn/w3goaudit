# test-data/

Solidity fixtures used by unit tests, integration tests, and the documented
developer workflows. Two top-level groups: **`security/`** holds the general
W3GoAudit-native vulnerability-detection fixtures (paired with
`templates/official/`); **`core/`** holds fixtures that exercise the tool's
core pipeline — parser/builder, WQL engine, and the CLI — rather than security
detection.

Each behavior has one canonical fixture lane. Benchmark-family fixtures live
under [`../benchmarks/fixtures/`](../benchmarks/fixtures/) instead of being
duplicated as aggregate files here.

| Group | What it holds | Used by |
|---|---|---|
| [`security/`](security/) | W3GoAudit-native fixtures for the official pack in [`../templates/official/`](../templates/official/) — deep bug-class matrices, focused engine regressions including metadata/MRO-exact caller identity and structurally pure unchecked-subtraction bounds, and promoted-detector fixtures with their safe controls. See [`security/README.md`](security/README.md). | `pkg/engine/*_test.go`, the documented full-pack scan |
| [`core/`](core/) | Core-pipeline / tool fixtures (not security detection) — see the sub-table below. | builder/reader/engine unit tests, the documented `build` + `engine-features` smoke tests |

### `core/` — pipeline & tool fixtures

| Subdirectory | What it exercises | Used by |
|---|---|---|
| [`core/build-database/`](core/build-database/) | Sixteen parser/builder/report fixtures numbered `01-..` through `15-..`. There are two distinct `10-*` cases: `10-interface-impl.sol` pins interface-to-implementation navigation, while `10-override-state-order.sol` pins asymmetric-diamond C3 order, storage order, and override binding. See the [folder README](core/build-database/README.md) for the complete matrix. | `pkg/builder/*_test.go`, `pkg/reader/*_test.go`, `pkg/report/nav_test.go`, the documented `w3goaudit build` smoke test |
| [`core/engine-features/`](core/engine-features/) | Canonical WQL operators (`and`, `any`, `sequence`, `in`, semantic groups, `arg.N`, and `tainted` including `user_controlled`). Paired with [`../templates/test/`](../templates/test/). Also `type-cast-guards.sol` and the `path-collision/{pkg-a,pkg-b}/tx-origin.sol` pair (same-named files in sibling packages). | `pkg/engine/*_test.go`, the documented `w3goaudit … --template templates/test/` smoke test |
| [`core/semantic-hardening/`](core/semantic-hardening/) | Reserved fixture lane for the internal program-point semantic analyzer, including future access-path, value-provenance, control-state merge, and CFG cases. No Solidity fixture is required by the initial model task. | `pkg/engine/semantic_*_test.go` as analyzer stages adopt source fixtures |
| [`core/extract/`](core/extract/) | CLI `extract` subcommands (entry, inheritance, source, context, bundle, workflow). Realistic multi-bug DeFi vault fixture. | `cmd/w3goaudit/extract_test.go`, `cmd/w3goaudit/extract*.go` examples, `docs/usage.md` |
| [`core/identity-collision/`](core/identity-collision/) | Same-named contracts in separate source paths, with intentionally distinct state/effects. | exact-identity builder, engine, navigation, and report regressions |

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
