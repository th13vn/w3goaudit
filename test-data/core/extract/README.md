# extract/

Realistic, multi-bug fixtures used as examples for the CLI `extract`
subcommands (`entry`, `inheritance`, `source`, `context`, `bundle`,
`workflow`). These are richer than the focused per-bug fixtures in
[`../../security/`](../../security/) — they exist so that `extract` examples in
`cmd/w3goaudit/extract*.go` and `docs/usage.md` reference a single, stable
contract with deep inheritance and realistic state.

`defi-vault.sol` is asserted by `cmd/w3goaudit/extract_test.go`, which builds a
database from it and checks the contract lookup, C3 inheritance linearization,
and entrypoint surface the `extract` commands depend on.

| File | Contains |
|---|---|
| `defi-vault.sol` | Complex DeFi vault: true bugs, false-positive bait, deep inheritance (`Context → Ownable → Pausable → ReentrancyGuard → DeFiVault`), complex state. Driving fixture for every `extract` example in the docs. |
