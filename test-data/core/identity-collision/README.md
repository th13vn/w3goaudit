# Identity collision fixture

The `a/` and `z/` sources deliberately declare contracts with the same short
name. Their functions and modifiers must remain attached to the exact
`file#Contract` identity throughout inheritance, call-graph construction,
semantic state effects, engine reachability, navigation, and report workflows.
The `a/` contract writes `safeCount`; the `z/` contract writes `destroyed` and
contains the only `selfdestruct`, so cross-file identity corruption is visible.
