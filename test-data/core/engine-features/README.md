# engine-features/

Fixtures exercising individual WQL engine operators. Each `.sol` file pairs
with a low-confidence template under [`../../../templates/test/`](../../../templates/test/);
the dev-workflow smoke test is:

```bash
w3goaudit test-data/core/engine-features/ --template templates/test/
```

| File | Operator under test | Match-vs-no-match |
|---|---|---|
| `01-sequence.sol` | `sequence:` (DFS-ordered descendants) | `VulnerableSequence` matches; `SafeSequence` does not (state-write precedes the call) |
| `02-inside.sol` | `has:` + `in:` (ancestor traversal) | `VulnerableInside` matches (`tx.origin` inside a `require`); `SafeInside` does not |
| `03-semantic-groups.sol` | `block: eth_transfer` semantic group | `UsesTransfer` matches; `NoTransfer` does not |
| `04-args-taint.sol` | `arg.N` + `tainted: parameter` | `VulnerableTransferFrom` matches (arg.0 from caller param); `SafeTransferFrom` does not (arg.0 is `msg.sender`) |
| `05-sequence-branches.sol` | `sequence` control-flow constraint (LCA-based branch-arm check) | `LinearSequence` matches; `BranchedExclusive` does not (call in `then` and write in `else` cannot co-execute) |

## Engine regression fixtures

These pair with Go tests in `pkg/engine/` rather than a `templates/test/`
template:

| Path | Guards | Driven by |
|---|---|---|
| `type-cast-guards.sol` | A `require(x != address(0))` type cast must not be mistaken for an outgoing call and trip a false reentrancy match. `Safe_AddressZeroCheck` / `Safe_MintBurnZero` must yield no findings. | `TestTypeCastsDoNotCreateReentrancyFindings` |
| `path-collision/pkg-a/tx-origin.sol`, `path-collision/pkg-b/tx-origin.sol` | Two files share the basename `tx-origin.sol` and both define `Vulnerable_TxOrigin`; each finding must keep its full source path, not just the basename. | `TestFindingLocationsUseExactFunctionIDSourceFile` |
