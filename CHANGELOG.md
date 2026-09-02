# Changelog

All notable changes to w3goaudit are documented here. This project adheres to
[Semantic Versioning](https://semver.org/). Output changes note the `data/*.json`
`schemaVersion`.

## Unreleased

### Added: deterministic semantic external-boundary evidence

- Builder Phase 8 now records versioned `ExternalBoundaryFact` evidence for
  Solidity and Yul external-control boundaries hosted by exact function or
  modifier scopes. `ExternalBoundaryFactsVersion` is `1.0.0`; `ScopeID` and
  `ScopeKind` keep modifier identities out of the function-only `FunctionID`.
- Facts retain exact or explicitly unresolved targets, bounded receiver/value/
  gas/argument provenance, structural result disposition and direct checks,
  direct host-scope state-effect ordering, reentry class, exact entry
  reachability, source ranges, and explicit limitations. Unknown evidence is
  never converted into a safe verdict.
- The SDK adds `GetExternalBoundaryByID`, `ExternalBoundarySnapshot`, and
  `QueryExternalBoundaries`. Agent queries require exact identities and a
  caller-supplied limit between 1 and `MaxExternalBoundaryQueryLimit` (200),
  paginate deterministically, and return deep copies.
- Canonical bundles add timestamp-free `data/interactions.json`, discovered by
  `manifest.files.data.interactions`. Contract reports render at most 50
  semantic rows and link to the complete artifact; legacy caches expose
  `available: false`, a rebuild limitation, and the human call-graph fallback.
- The WQL attribute catalog now accepts the protocol-neutral boundary bridge,
  including `boundary_result_checked`, without adding protocol-specific engine
  behavior or changing any official template.

### Compatibility

- Output schema remains `2.0.0`; there is no CLI break. Database, manifest, and
  SDK fields are additive. Existing W3Solidity consumers may ignore
  `files.data.interactions` and continue reading nav, explorer, findings, and
  xref artifacts.
- Core remains offline, deterministic, and independent of models, credentials,
  providers, callbacks, or AI triage. External Assistants consume evidence but
  cannot modify official scanner findings.
- The official rule pack is unchanged. This entry describes unreleased local
  work only and does not claim a tag, push, publication, or release.

## v0.5.0 - 2026-09-01

Human-report consolidation release. The scanner remains deterministic and
model-independent, the machine output schema 2.0.0 and `data/*.json` shapes are
preserved, and existing SDK formatters remain callable. This local release
metadata is prepared without a tag or publication.

### Changed: one navigable audit instead of fragmented human files

- The canonical result folder now contains bounded `README.md`, consolidated
  `audit.md`, always-on SARIF and log files, unchanged machine data, and one
  collision-safe Markdown deep dive per main contract under `contracts/`.
- `--html` emits one self-contained `audit.html` with full escaped finding
  evidence, metrics, analysis limitations, rules hit, contract and state
  summaries, safe links, offline assets, accessibility, and print styling.
- Rescans remove split Markdown/HTML, fragmented contract folders, legacy AI
  artifacts, and a stale manifest before writing. All paths are planned before
  mutation, and the new manifest is written last.
- `files.audit`, optional `files.auditHtml`, and `contracts[].report` are the
  canonical discovery fields. During v0.5.x, manifest compatibility aliases
  `summary`, `overview`, and `findings` point to `audit.md`; HTML aliases point
  to `audit.html`.
- W3Solidity compatibility remains through unchanged
  `files.data.{nav,explorer,findings,xref}` paths and structured artifacts.

## v0.4.3 - 2026-07-31

Precision release, cut from real-corpus review of the v0.4.2 output. No CLI, SDK,
or output-schema change — schema stays `2.0.0`. Two false-positive classes are
removed; on the 470-contract corpus the scan goes **44 → 41 findings** with no
true positive lost. Ships with template pack **v2.1.1**.

One fix lives in the pack (`reentrancy-pattern.yaml`) and one in the engine
(`collectStateWriteTargets`), so `--update-templates` alone delivers only half of
this release — upgrade the binary too.

### Fixed: `delegatecall` no longer counts as reentrancy (`HIGH-REENTRANCY-PATTERN`)

The CEI detector matched `delegatecall` alongside ETH-bearing and raw low-level
calls. Delegatecall executes the callee's bytecode in **this** contract's context
— same storage, same guard slot — so re-entry through it is the contract running
its own code, not attacker-injected reentry. Real targets are trusted, admin-set
sidecars or literally `address(this)`.

On the 470-contract corpus this was **3 of 7** `HIGH-REENTRANCY-PATTERN` findings,
all noise: CrocSwap `ProxyCaller.callSwap`/`callCrossFlag`
(`proxyPaths_[CONST].delegatecall(...)`) and Eesee `MulticallPayable.multicall`
(`address(this).delegatecall(...)`). No true positive is lost — an
attacker-influenced delegatecall target is arbitrary code execution and is
already reported, at higher severity, by `CRITICAL-DELEGATECALL-USER-INPUT`.

Removing the branch also unshadowed one raw-`.call` site that the delegatecall
match had been winning over on the same entry point (CrocSwap
`TransferHelper.safeTransferFrom`, `token.call(abi.encodeWithSelector(...))` from
`HotProxy.userCmd`). Corpus total: 44 → 42 findings.

Regression: `TestDelegatecallIsNotReentrancy` in
`pkg/engine/false_positive_regression_test.go`.

### Fixed: an assembly storage-slot init flag now proves a one-time-init guard

`HIGH-UNPROTECTED-INITIALIZER` reported Axelar's `InterchainToken.init()`, which
opens with `if (_isInitialized()) revert AlreadyInitialized();`. The
`initializer_guarded` preset needs the same flag to be read under a check and
written; the flag here is an explicit storage slot touched only from inline
assembly (`sload(INITIALIZED_SLOT)` in `_isInitialized()`,
`sstore(INITIALIZED_SLOT, true)` in `_initialize()`). `collectStateWriteTargets`
matched only `stmt.assign`, so the read was collected and the write never was, and
the mutex could not be proven.

`asm.sstore(SLOT, …)` now counts as a write to `SLOT`, matching the engine's
`state_write` block, which already treated it that way. This also lets
assembly-slot reentrancy mutexes (Solady-style) prove `reentrancy_guarded`, since
`modifierBodyProvesMutex` shares the collector. Corpus total: 42 → 41 findings.

Regression: `AsmSlotFlag` (safe) and `AsmSlotMismatch` (the write lands on a
different slot, still reported) in `TestOneTimeInitGuardIsRecognized`.

## v0.4.2 - 2026-07-29

Correctness and coverage release. Output schema stays `2.0.0`. One new CLI flag
(`--strict-parse`) and one new config key (`scan.strict_parse`); every other
change is a fix or an addition to the shipped detector pack.

### Fixed: whole source files were silently dropped (solast-go v0.1.7 → v0.1.10)

Three parser gaps, each with the same failure mode: an unhandled token, `expect()`
not advancing in tolerant mode, and the **remainder of the file shredded** — not
just the offending construct.

- `assembly ("memory-safe") { … }` — the optional `assemblyFlags` group, standard
  since Solidity 0.8.13 and pervasive in OpenZeppelin v5, Solady, and Solmate.
- Dotted Yul paths (`sig.offset`, `x.slot`). In operand position the `.`
  desynchronized the block; in assignment-target position it silently produced a
  truncated name with no error reported at all.
- `hex"1900"` and `unicode"…"` literal prefixes. The token types existed and the
  parser already branched on them, but the lexer never produced either.

Measured on a real OpenZeppelin v5 Foundry project: **488 `parse.recovered`
diagnostics → 0**, and functions analyzed **247 → 352 (+43%)**. `Math.sol`,
`Strings.sol`, `ECDSA.sol`, `EIP712.sol`, `MessageHashUtils.sol`, `SafeERC20.sol`,
`Bytes.sol`, `ShortStrings.sol`, and `StorageSlot.sol` previously yielded no usable
AST, so every detector was blind inside them.

### Added: parse-coverage loss is loud, and `--strict-parse`

The only prior signal for the above was `analysisComplete: false` inside
`data/manifest.json`, so a confident-looking finding count could hide a file the
analyzer never read. Parse loss is a different class from an unresolved reference:
an unresolved import leaves the AST intact and merely imprecise, whereas a missing
AST hides declarations from **every** detector.

- `parse.recovered`/`parse.skipped` are now summarized on stderr during the build
  (`emitParseDiagnostics`) and in the console result (`printParseLossTo`), naming
  the affected files and pointing at the new flag.
- `--strict-parse` (root command and `build`, plus `scan.strict_parse` in
  `~/.w3goaudit/config.yml`) fails before template execution and report writing,
  with the same source/`--db` parity and explicit-flag-wins precedence as
  `--strict-imports`.

### Fixed: `version:` compared a pragma range to a single version

`extractVersion` took the **first** `major.minor.patch` in the pragma and compared
it as a point, which was wrong in both directions:

- `pragma solidity >=0.7.0 <0.9.0;` yielded `0.7.0`, so a `version: ">=0.8.0"`
  detector was silently skipped for code that compiles on 0.8.x — a false negative
  on a very common spelling (Uniswap V3 era, much of the library ecosystem).
- `^0.8` has no patch, so extraction returned `""` and the gate failed **open**.

`checkVersion` now intersects the constraint with the whole range the pragma
permits, understanding caret, tilde, comparator chains, `||` alternatives, and
partial versions. An unparseable pragma or constraint still skips the check rather
than excluding the file. The dead `extractVersion`/`compareVersions`/
`parseVersionParts` helpers were removed in favor of `parseVersionTriple`/
`compareTriples`.

### Fixed: access-control precision depended on variable naming

The storage-authority vocabulary that decides whether
`require(<mapping>[msg.sender])` proves authorization listed only eleven terms, so
identical code produced a false positive or not depending on the author's naming:
`operators` and `whitelist` were recognized while `keepers`, `managers`,
`controllers`, `governors`, and `trustedCallers` were not. It is now one
documented, closed set of privileged-principal nouns, still deliberately excluding
value-bearing names (balance, deposit, stake, share, nonce) and inverted denylists
(blacklist), because treating those as authorization would suppress real findings.
Competitive benchmark unchanged (TP 109 / FP 41 / FN 0), so the widening cost no
recall.

### Fixed: `CallGraph.HasCycle` always returned false on a `--db` cache

`HasCycle` read the unexported adjacency map directly instead of going through
`EnsureIndex`. Those maps do not survive JSON, so on a loaded database it walked no
edges and reported "no cycle" for every input — a silent wrong answer.

### Fixed: a truncated import walk could bind the wrong dependency

`resolveBySuffixMatch` bounds its `lib/`/`node_modules/` walk, but uniqueness is
only meaningful over a complete view: a match that looks unique among the files
seen so far may be ambiguous in the ones skipped. Hitting the cap now abstains and
logs why, leaving the import unresolved (already a durable `import.unresolved`
diagnostic) instead of resolving from a partial view.

### Added: 14 detectors promoted into the shipped `official/` pack (25 → 39)

Generic, benchmark-validated detectors that previously existed only in the
dev-only, git-ignored benchmark lane, so a released binary never ran them. Each
ships with vulnerable **and** safe fixtures under `test-data/security/` and a
`pkg/engine/promoted_templates_test.go` assertion that doubles as a
false-positive gate.

- Read-only reentrancy: `HIGH-READONLY-REENTRANCY-CURVE`,
  `HIGH-READONLY-REENTRANCY-BALANCER`.
- AMM integration: `HIGH-NO-SLIPPAGE-CHECK`,
  `HIGH-UNISWAP-CALLBACK-UNPROTECTED`, `HIGH-UNISWAP-V4-HOOK-UNPROTECTED`.
- Access control: `HIGH-ORACLE-PRICE-UPDATE-UNRESTRICTED`,
  `HIGH-ERC20-PUBLIC-BURN`.
- Callback reentrancy: `HIGH-ERC721-CALLBACK-REENTRANCY`,
  `HIGH-ERC777-CALLBACK-REENTRANCY`.
- Oracles: `MEDIUM-STALE-ORACLE-DATA`,
  `MEDIUM-DEPRECATED-CHAINLINK-LATESTANSWER`, `MEDIUM-ORACLE-LP-SPOT-PRICE`,
  `MEDIUM-ORACLE-CURVE-SPOT-PRICE`.
- Source integrity: `MEDIUM-BIDI-CHARACTERS` (Trojan Source).

A fifteenth candidate — a generic "external call then state write" reentrancy rule
— was evaluated and **rejected**: it fired on 36 sites across the repository
fixtures, 17 of them deliberate safe controls, because pull-then-credit is the
correct ERC20 deposit shape. The precise signal it reached for is already covered
by the two callback-reentrancy detectors above, so it stays in the benchmark lane.
`templates/AI.md` records this as the worked example of the precision bar.

### Changed: benchmark reports state their own methodology

Every generated `benchmark.md` now names the template directory each case ran with
and carries a "How to read these numbers" section explaining that the corpus and
answer key are first-party and that cases run lane-specific templates rather than
the shipped `official/` pack — so the detection rate is a regression signal, not
evidence of coverage on unseen code. `benchmarks/README.md` says the same. No
metric or threshold changed (precision >= 0.65, recall >= 0.95, zero failed cases).

### Changed: findings point at the dangerous statement (new default)

`Finding.Location` now uses matched-node attribution: file, line, columns, bytes,
contract, and function all describe the statement the detector matched. The
externally-callable entry point is not lost — it travels in `entryPoint` (the
auditor-actionable "fix here" hop) and `reachability`.

Verifier attribution, the previous default, took `file`/`line` from the matched node
but `contract`/`function` from the entry function, so an interprocedural finding
described **two different places at once**. On a real 470-file scan 8 of 52 findings
disagreed with themselves that way: one read `CrocSwapDex.userCmdRelayer` while its
line pointed into `ProxyCaller.sol`, and an editor jumping to the location opened a
`using` statement in an unrelated file. It also produced impossible coordinates —
line 185 of a 112-line `UUPSUpgradeable.sol`, because the delegatecall is really in
`AddressUpgradeable.sol`.

After the change, on that same project: 0 findings whose line falls outside its own
file, 0 whose reported contract does not enclose the reported line.

- New `--location-source matched|verifier` CLI flag. The docs previously stated no
  such flag existed.
- `W3GOAUDIT_LOCATION_FROM_MATCHED_NODE` now accepts `verifier`/`0`/`false` as well
  as `matched`/`1`/`true`, and still takes precedence over the API.
- New `LocationSourceDefault` zero value, so
  `SetLocationSource(LocationSourceVerifier)` means "verifier, explicitly" rather
  than being indistinguishable from an unset field.
- **Consumers that index findings by entry function should read `EntryPoint`**, or
  pass `--location-source verifier`. Seven repository tests were updated to assert on
  the entry hop rather than on `Location`; the matching behavior is unchanged, only
  the label moved.

### Fixed: seven false-positive classes found by scanning 470 real contracts

Scanning a corpus of verified block-explorer sources (Kyber, Euler, CrocSwap,
OpenZeppelin, Uniswap v4) produced 103 findings, of which 39 were false or
duplicated. Each class below was reproduced from the real source, fixed, and pinned
by a regression test in `pkg/engine/false_positive_regression_test.go` or
`pkg/types/function_test.go`. Net effect on that corpus: **103 → 63 findings (39%
fewer)** with no true positive lost; the competitive benchmark improved slightly
(FP 41 → 40, precision 72.67% → 73.15%, recall still 100%).

1. **A key does not taint the value it selects.** Expression taint unioned every
   child, so `proxyPaths_[callpath].delegatecall(...)` looked attacker-controlled
   because the caller chose the *index* — even though only governance can populate
   the mapping. Value provenance now comes from the base/receiver chain only, which
   is the rule `lvalueStateVarName` already used. `from[i]` still inherits its
   caller-supplied base's taint. Fixed CRITICAL reports on the standard
   proxy-dispatch idiom (CrocSwapDex, Curve, OZ UUPS).
2. **A call ancestor does not invalidate a bound proof.** `require(a >= b);
   unchecked { f(..., a - b); }` was reported, because the subtraction's expression
   path has a call ancestor. Solidity evaluates arguments before the callee runs, so
   the enclosing call cannot mutate the operands; only effectful SIBLING arguments
   can, and that check is unchanged. Nine of 21 unchecked-arithmetic findings were
   inside OpenZeppelin's own `ERC20._spendAllowance`, `ERC20.decreaseAllowance`, and
   `SafeERC20.safeDecreaseAllowance`. The repository fixture that was meant to cover
   this used a plain assignment, which is why the real shape was never caught.
3. **Reentrancy guards are proven from bodies, not names.** `checkReentrancyGuarded`
   matched a name regex, so `reEntrantLock` was recognized while its siblings
   `reEntrantAgent` and `reEntrantApproved` — identical mutexes in the same
   contract — were not. `types.Function.HasReentrancyGuard` now requires the
   modifier to check a state variable and write it before `_;`. Names remain a
   fallback only for an unresolvable body.
4. **One dangerous site is one finding.** Each entry function was reported
   separately for the same statement in a shared helper: six `removeLiquidity*`
   wrappers gave six findings for one line, and 20 of 92 findings were such repeats.
   `dedupeReachedSites` collapses them and moves the other entry points into
   `Context["additionalEntryPoints"]`, so reachability information is kept rather
   than dropped.
5. **A finding's file now contains its line.** In the default location mode the
   line came from the matched node but the file from the entry function, so an
   interprocedural match produced a location that does not exist — line 185 of a
   112-line `UUPSUpgradeable.sol`, because the `delegatecall` is in
   `AddressUpgradeable.sol`. Such a finding reads as a false positive even when
   sound, since nothing is there to inspect. Function/Contract stay
   verifier-derived, so JSON/SARIF consumers are unaffected.
6. **An override shadows its base even when it is not an entry point.**
   Entry-function resolution checked `IsEntrypoint()` before the override dedup, so
   a `view`/`pure` override never claimed its selector and an inherited nonpayable
   INTERFACE stub was admitted instead. Every access-control detector then fired on
   a bodyless declaration (7 false positives on Uniswap v4 `IHooks`).
7. **An abstract auth hook resolves to its override.** `access_controlled` analyzed
   `UUPSUpgradeable._authorizeUpgrade`'s bodyless `internal virtual;` declaration
   instead of the deploying contract's `internal override onlyOwner {}`, reporting
   the ecosystem's most standard upgrade guard as an unprotected upgrade. The new
   `IsAccessControlledIn(db, runtime)` dispatches `virtual` internal calls through
   the runtime MRO. `super.f()` is excluded, because redirecting it to the
   most-derived declaration points it back at the caller (Euler's
   `EVault.transferFrom` is `return super.transferFrom(...)`).

A second pass over the same corpus, auditing every surviving finding against the
real source, found seven more classes. Combined with the first pass: **103 → 52
findings (50% fewer)**, benchmark recall still 100% and precision still 73.15%.

8. **A pinned selector is not an arbitrary call.** `arbitrary-low-level-call`
   required only that the calldata be tainted, so
   `token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, value))`
   — Uniswap's `TransferHelper` — was reported in four separate projects. The caller
   chooses the arguments but not the FUNCTION, which is what a confused deputy needs.
   The rule now requires either a raw caller-supplied calldata blob or an
   attacker-chosen selector.
9. **`has: {receiver: true}` matched a nested call's receiver.** It searches every
   descendant, so CrocSwapDex's
   `proxyPaths_[CONST].delegatecall(abi.encodeWithSignature(…, curve.pullPriceTick(), …))`
   was CRITICAL because `curve` is caller-derived — not because the target was.
   New `receiver:` nested-rule matcher constrains the call's **direct** receiver
   (`matchDirectReceiver`); `receiver: true` keeps its attribute meaning.
10. **ECDSA malleability needs a signature-keyed replay guard.** Any caller-derived
    index after a `recover` matched, so `battles[battleId] = …` — an id-keyed claim
    flag, i.e. the correct pattern — was reported. The index must now reference the
    signature.
11. **`getRate` is too generic to identify Balancer.** The promoted
    `readonly-reentrancy-balancer` detector matched any `getRate()`, firing three
    times on Shell/Curve `Assimilators.getRate`. Narrowed to the Vault-specific
    `getPoolTokens` shape; the rate-provider variant stays in the benchmark lane,
    where the corpus pins the receiver.
12. **A custom role system read through assembly.** Axelar's
    `if (!_hasRole(_getRoles(msg.sender), role)) revert` reads the role bitmap with
    `assembly { accountRoles := sload(key) }`, which the body analysis cannot follow.
    `authorityCallProvesAuthorization` accepts it, but only with four signals at
    once — authority name, forwarded caller, all other operands fixed, and the
    caller-carrying argument resolving to an assembly storage read. The last signal
    is what keeps a `return true` decoy rejected.
13. **An unresolvable applied modifier is undetermined, not absent.** Axelar's
    role-gated `burn` was reported as a public burn purely because
    `@axelar-network/…` imports did not resolve, leaving `RolesBase` out of the exact
    MRO. A recorded modifier application the analyzer cannot see is now undetermined;
    unresolved imports are already durable diagnostics rather than a reason to
    manufacture a finding. A bare name in `Function.Modifiers` still proves nothing,
    and `IsAccessControlled(nil)` is still false.

14. **Binary operations had no source location at all** (solast-go v0.1.10). Every
    level of the precedence ladder built a `BinaryOperation` without calling
    `setLocation` — invisible because `setLocation` already had a case for that node
    type, so nothing reached it. Findings anchored on an operation therefore reported
    the enclosing FUNCTION's line: `divide-before-multiply`, `boolean-cst`,
    `incorrect-exp`, and `unchecked-arithmetic` were all affected.
15. **`unchecked-arithmetic` rebuilt around what is actually exploitable.** It now
    anchors on the operation rather than the `unchecked` block (a gas-optimized
    whole-function wrapper produced one unactionable finding for an entire body), and
    covers `*`, `-`, and `+` only when an operand is caller-controlled. `/` cannot
    overflow; counter and nonce increments cannot be driven to the type maximum. Two
    bound-proof gaps were fixed alongside: a non-negative integer literal now
    qualifies as an unsigned bound operand (so `require(n > 0); … n - 1` is provable
    at all — previously EVERY `x - 1` in an `unchecked` block was unconditionally
    reported), and a guard bounding the minuend below by a literal proves a literal
    subtrahend.

A fourth pass took the remaining findings class by class. Cumulative on the same
corpus: **103 → 44 findings (57% fewer)**, benchmark still TP 109 / FP 40 / recall
100% / precision 73.15%.

16. **One-time-init guards are now proven, not name-matched.** The detector knew only
    the OpenZeppelin `initializer` modifier and a guard literally naming
    `_initializersDisabled`, so Euler's `if (initialized) revert; initialized = true;`
    and Axelar's split `if (_isInitialized()) revert; _initialize();` were both
    reported as unprotected initializers. New `initializer_guarded` preset
    (`HasOneTimeInitGuardIn`) proves the same mutex shape the reentrancy work already
    proves: an enforcing check reads a state flag that the function, a resolved
    internal helper, or a sibling such as the constructor sets. The name-specific
    carve-out is gone.
17. **`boolean-cst` narrowed to constant folding.** `a && false` and `if (true)` leave
    a dead branch — a real logic error. `x == false` is a verbose `!x`, which is a
    style preference and how CrocSwap spells its mutex checks
    (`require(msgValSpent_ == false, "DS")`); reporting it at MEDIUM contradicted the
    pack's own policy of excluding style rules.
18. **`weak-prng` ignores power-of-two truncation.** `uint32(block.timestamp % 2**32)`
    is Uniswap V2's `_update` fitting a timestamp into a packed slot, not a random
    draw. A weak PRNG takes the modulo by a participant count.
19. **`dangerous-strict-equality` allows the same-block cache check.**
    `if (reserve.lastUpdateTimestamp == block.timestamp) return cachedIndex;` is
    Aave's "already updated this block" short-circuit against a contract-written
    value; all three real occurrences carried an explicit
    `// slither-disable-next-line incorrect-equality`. Block-clock comparisons are now
    reported only when the other operand is caller-controlled.

### Fixed: benchmark scoring follows the new attribution

The harness matched corpus expectations against `Location.contract`/`function` only.
With matched-node attribution an interprocedural detection is located at the callee
that hosts the statement, so `VulnerableBadTransferFromInherited.deposit` was scored
as a miss even though the finding existed with exactly that `entryPoint`. The
w3goaudit adapter now scores by entry point, falling back to the location.

Emitting BOTH identities also restores recall but inflates false positives, because
the identity that does not match the key is counted as extra noise — one row per
finding, keyed on the entry point, is the correct shape. For a non-interprocedural
finding the two identities are the same function anyway.

Known limitation, deliberately not "fixed": CrocSwapDex's sidecar `userCmd` entry
points are reachable only via `delegatecall` from the parent contract, which holds the
reentrancy lock in shared storage. Proving that needs cross-contract storage-layout
modeling; Slither reports these too.

One behavior change is deliberate and worth calling out: intra-branch duplicate
findings for an identical precise site are now collapsed rather than retained.
`TestOrCompositionIdentityPreservesIntraBranchDuplicates` pinned the old behavior
and has been retargeted; it described the `or:`-union implementation rather than
anything a user wanted.

### Test coverage

- `pkg/types` 56.9% → 69.3%, concentrated on the false-positive-sensitive
  access-control vocabulary, the call-graph API and its JSON round-trip, the
  diagnostic helpers, and the database identity surface.
- New `FuzzParseTemplate` over the WQL loader — the project's only untrusted input
  surface besides Solidity source. 433k executions, no crashes.

## v0.4.1 - 2026-07-27

Additive release on top of v0.4.0. Output schema stays `2.0.0`: the new
`data/xref.json` artifact and the new `Database`/`Contract`/`Function` fields are
purely additive, and every existing artifact keeps its shape. No template,
WQL, or CLI-flag changes.

### Precise cross-reference artifact (`data/xref.json`)

A third extension data-layer artifact (`report.BuildXrefJSON`,
`pkg/report/xref.go`), written by `WriteBundle` and indexed in `manifest.json`
under `files.data.xref`. It gives an editor exact go-to-definition and
find-references with **no regex fallback**:

- `declarations[]` — every jump target keyed by its canonical id, with `kind` ∈
  `contract|interface|library|function|modifier|event|error|struct|enum|stateVar|parameter|local|udvt`
  and the name-token range (falling back to the declaration span).
- `references[]` — one entry per bound occurrence: the file, the exact token
  range, the declaration `refId`, and `refKind` ∈
  `state_var|parameter|local_var|function|library|event|error|modifier|type|udvt`.
- Bound occurrence coverage: identifiers (state vars, parameters, locals),
  resolved internal/external/self/super and library `using` calls, UDVT
  `wrap`/`unwrap`, type casts, `revert`/`emit` targets, and applied modifiers.
- Both tables are total-order sorted, so `xref.json` is byte-stable across runs.

Supporting builder/type work, all additive:

- Backfilled identifier source positions from a located parent (member/call
  receivers, index bases, assignment lvalues), since solast-go ranges postfix
  expressions but not every interior operand. What stays unlocated is **omitted
  rather than approximated**.
- Captured custom error declarations (`Contract.Errors`, new `types.ErrorDef`)
  and bound `revert X()` / `emit E()` occurrences to them.
- Captured user-defined value types (`Database.UserDefinedValueTypes`, new
  `types.UDVTDef` keyed `absPath#Name`, plus `Database.UniqueUDVTByName`) and
  bound `T.wrap`/`T.unwrap` to the declaration. An ambiguous name binds to
  nothing.
- Captured applied-modifier usages with name-token ranges
  (`Function.ModifierUsages`, new `types.ModifierUsage`); the owner is resolved
  along the C3 linearization.
- Bound AST call nodes to their resolved call-graph target by call-site byte,
  resolved non-call member-field reads through the receiver's type contract id,
  and bound type-cast callees to their type declaration.

See [`docs/extension-output.md`](./docs/extension-output.md) for the full schema.

### Import resolution — last-resort heuristics

Verified sources fetched from block explorers (Etherscan standard-JSON /
multi-file) frequently ship prefixes such as `@prb/math/` or
`@openzeppelin/contracts/` with **no remappings file**, so the prefix cannot be
predicted, only reconstructed. Two heuristics (`pkg/reader/fallback.go`) now run
**only** for an import that remappings and the `node_modules/`/`lib/`/root stat
fallbacks all failed to resolve — i.e. one that would otherwise be recorded as
`import.unresolved`:

- `resolveByConvention` rewrites well-known prefixes to the layouts dependency
  managers conventionally install them under (OpenZeppelin + upgradeable,
  prb-math/prb-test, forge-std, ds-test, solmate/rari-solmate, solady,
  Uniswap v2/v3), longest-prefix-first, first existing file wins.
- `resolveBySuffixMatch` picks the `.sol` file under `lib/`/`node_modules/`
  sharing the longest trailing path-segment suffix with the import, requiring
  **at least two** aligned segments and **uniqueness** at the longest length.

Both accept only an existing regular file contained within the owning
sub-project, abstain on ambiguity, and never invent a path; explicit remappings
always win. An import neither heuristic can resolve still returns unchanged and
still records its unresolved-import diagnostic, so `--strict-imports` behavior is
unchanged.

### Documentation

- Documented `data/xref.json` end to end: `README.md` (feature bullet +
  result-folder tree + docs index), root `AI.md` (pipeline, invariants,
  report notes), `docs/usage.md`, `docs/workflows.md`,
  `docs/project-overview.md`, `docs/internals.md` (new §5.2.1 on xref reference
  binding), `docs/sdk.md` (`BuildXrefJSON` + `XrefJSON`/`XrefDecl`/`XrefRef`),
  and `docs/extension-output.md`.
- Documented the import-resolution heuristics in `README.md`,
  root `AI.md`, `docs/internals.md`, and `pkg/reader/AI.md`.
- Corrected the stale `Contract` struct in `pkg/types/AI.md`
  (`StateVariables`, not `StateVars`; `Kind` is a `ContractKind`; `Errors`,
  `Modifiers`, `Enums`, `IsAbstract`, `UsingDirectives` were missing) and
  documented the new types alongside it.
- The scan console summary now lists `nav.json`, `explorer.json`, and
  `xref.json` under `data/`, matching what is actually written (it previously
  listed only the first five).

### Quality gate

Unchanged from v0.4.0 — the competitive gate still passes at TP 109 / FP 41 /
FN 0 (precision 72.67%, recall 100%, zero failed cases), stored as
`benchmarks/2026-07-27-v0.4.1-xref-import-fallback.md`. `go vet ./...` and
`go test ./...` are clean.

## v0.4.0 - 2026-07-20

Major release. Precise source locations (**output schema 2.0.0**, breaking), the
canonical WQL query language with `and:` / `or:` composition, a full
correctness-closure and hardening pass, and the competitive benchmark moved to a
local-CLI quality gate (`scripts/benchmark/`). The gate passes at TP 109 / FP 41
/ FN 0 — precision 72.67%, recall 100%. Pairs with the **w3goaudit-templates
v2.0.0** canonical-WQL pack.

### Benchmark harness (local CLI + relocation)

- The benchmark harness under `scripts/` is **dev-only and git-ignored** — not
  part of a fresh clone or the published release. `benchmarks/` still tracks the
  dated result reports (`yyyy-mm-dd-<commit-slug>.md`). Benchmark-dependent Go
  tests skip automatically when the harness is absent, so `go test ./...` stays
  green on a clean checkout.


- Moved the competitive benchmark harness (runner, scoring, adapters, corpora,
  fixtures, WQL ports, Docker files, threshold gate) from `benchmarks/` to
  `scripts/benchmark/`. `benchmarks/` now stores results only: tracked dated
  reports named `yyyy-mm-dd-<commit-slug>.md` plus the Git-ignored
  `benchmarks/results/` run-output scratch directory.
- The w3goaudit quality gate now runs via the local CLI
  (`scripts/benchmark/run_benchmark.py` + `assert_thresholds.py`); Docker
  Compose remains only for the multi-tool comparison against
  Slither/Semgrep/4naly3er.

### Correctness closure (Project 1)

- Corrected Solidity `for` AST order to initialization, condition, body, then
  post, and completed state-write coverage for dynamic-storage-array
  `push`/`pop`, state-targeted `delete`/`++`/`--`, and assembly `sstore`.
  Storage-array mutations are modeled as `stmt.state_mutation`, not calls.
- Materialized exact contract, function, variable, parameter, and modifier
  declaration nodes with exact source spans. Active inherited functions are
  deduplicated by canonical selector so derived overrides replace base
  implementations while overloads remain distinct.
- Made `guarded_by` evaluate inline guards and exact applied modifier bodies.
  Modifier names remain descriptive and no longer imply access control by
  themselves.
- Aligned where-only query defaults and validation: actionable AST evidence
  defaults to `entry_function`, while context-only queries fail because they
  cannot anchor a finding. Programmatic evaluator validation rejects the same
  invalid values as loaded WQL.
- Corrected public documentation for `Function.Selector` canonical text versus
  four-byte `Function.Signature`, location units, location-source behavior,
  report indexing, cached source content, and extension output examples.

### Canonical WQL and query composition

A WQL document is meta plus one query: block. All 106 repository templates use
that canonical shape. The final competitive benchmark gate passes with TP 109,
FP 41, FN 0, precision 72.6666666667%, recall 100%, and zero failed cases.

- **`query.or:`** — one detector, several alternative shapes: a list of
  complete branch queries under one `meta`. Each branch anchors its own
  finding (own `select`, `where`, optional `from`; a query-level `from` is
  the shared default, and cross-scope branches are allowed). Lowered to one
  `QueryBlock` per branch (new `Template.Queries` IR field, additive JSON);
  the engine executes every block and unions the findings, deduplicating
  identical matched locations. Unknown-kind results are provisional: the first
  concrete kind at the same span replaces the unknown result, making
  unknown-first and unknown-last branch orders identical while preserving
  distinct concrete kinds.
- **`query.and:`** — multi-site joined findings: a query-level `from:` names
  the join scope (contract scopes join per contract via the synthetic
  inheritance-aware AST; function scopes per function), and every branch
  (own `select`/`where`/`label:`) must match in the same scope instance.
  Branch sites surface in `Finding.Related` under their labels. Lowered onto
  evaluator `Rule.All` branch machinery. Context-level
  matchers are rejected inside `and:` branches (a filter applies to the
  whole scope instance); absence-only branches are also rejected because every
  branch must provide reportable primary/related evidence. Positive synthetic
  contract-root branches emit contract/file related sites.
- One composition level; `and:`/`or:` cannot mix with each other or with a
  sibling `select:`/`where:`; malformed shapes fail at load with pointed
  errors.
- Explicitly authored query/branch scalars and matcher lists must be non-null
  and non-empty. Vacuous nested matchers, empty required strings,
  `unchecked_var: false`, and signed/non-decimal `arg.N` keys fail at load;
  negative programmatic indexes also fail safely instead of panicking. The
  strict matrix covers null and empty `select`/`from`/`where`/`label` values in
  both `and:` and `or:` branches.
- **`arg.any:`** — matches when SOME positional call argument satisfies the
  sub-rule (receivers/call options excluded, as with `arg.N`).
- **`and:` in `where`** — the canonical explicit conjunction.
- **Repeated sibling `not:` correctness** – implicit-conjunction negations are
  preserved independently as `(not A) and (not B)`, fixing false positives for
  access-controlled or initializer-modified upgrade functions and
  `onlyPoolManager`-protected Uniswap v4 callbacks.
- Contract-scope findings now borrow function ownership and exact spans only
  from a primary match with a real source line. Location-less contract matches,
  including proxy storage-collision regex combinations, remain attributed to
  the verified contract and file instead of a synthetic ancestor function.
- The Decurity-inspired arithmetic-underflow detector now applies semantic
  `unchecked_var` range-guard analysis to explicit Solidity 0.8 `unchecked`
  binary `-` and assignment `-=` subtraction. It clears only exact unsigned
  operand bounds enforced on the operation's path; reversed/unrelated guards,
  non-terminating branches, intervening statements, effectful condition
  operands or additional guard arguments, signed arithmetic, and ordinary
  checked subtraction remain findings or controls as appropriate.
- Caller-identity taint recognizes only `msg.sender`, `tx.origin`, and exact
  zero-argument internal `_msgSender()` helpers confirmed by recorded metadata
  and exact MRO resolution when available. Empty or unresolvable database state
  is unavailable context rather than negative proof, so exact synthetic
  zero-argument internal calls retain the compatibility fallback; once exact
  owner/MRO context is available, a missing helper or nonzero overload
  disproves caller identity. Same-named identifiers, state/local/parameter
  names, and external/self/unresolved calls retain parameter/local/state
  provenance in both taint and access-control analysis.
- Sequence backtracking now restores abandoned primary anchors. Name-only
  member matches and cross-function contract joins retain exact related
  evidence; matched-node locations use the primary span plus the final trace
  host; query-union dedup is span-based with optional kind evidence.
- The canonical accessible-selfdestruct benchmark detector now treats any
  unauthenticated reachable destruction as vulnerable, including fixed
  beneficiaries and Solidity/helper/cast/Yul forms; access control remains the
  safe property.
- Sequence matching now uses one execution-event partial order locally and
  interprocedurally. Receiver, call-option, and argument subtrees precede the
  call; the call precedes an inlined callee; ordinary sibling statements retain
  source order; distinct pre-call siblings may match either relative order.
  Per-occurrence reachability and caller/callee arm tokens now reject
  cross-tree mutually exclusive matches and preserve the selected chain when a
  callee AST is reused.
- Select-less sequences now require positive actionable evidence in their first
  step. Query-level `and:` branches require both a positive reportable anchor
  and traceable AST evidence, so absence-only and regex-only joins fail at load;
  regex remains supported as refinement and in simple queries.
- Programmatic Rule compatibility cloning now applies the depth-64 and active
  cycle checks to nested `Attr` maps and slices. Self/mixed cycles and depth 65
  fail closed without caller mutation, while depth 64 and shared DAGs remain
  valid.
- Added additive per-occurrence `SourceFile.ImportBindings` JSON with raw and
  canonical paths, namespace aliases, and named symbol aliases. Exact resolution
  recognizes `Parent`/`V.Base`, hides aliased original bare names, exposes
  diagnostic-aware resolution statuses, and preserves behavior across cache
  round trips.
- Parsed calls with known arguments no longer resolve a unique same-name target
  of the wrong arity. Exact target fields stay empty and one durable
  `identity.unresolved` diagnostic records the observed arity.
- `FunctionCall.argCount` now distinguishes absent legacy JSON (`-1`) from a
  genuine zero-argument call, and zero is always serialized. Every unresolved
  legacy MRO entry now records an incomplete identity diagnostic.
- Report graphs, state matrices, and workflows share one exact call resolver;
  navigation publishes only exact resolved callee IDs. `extract diff` now uses
  source-relative exact contract keys and full selectors across checkout roots.
- Benchmark fallback attribution now sanitizes Solidity comments and quoted
  strings with a length- and newline-preserving lexer before both declaration
  matching and brace counting, preventing fake declarations and quoted braces
  from corrupting Semgrep/4naly3er locations.
- Closed five integrated review gaps: `Rule.IsStateVar` containers now share
  bounded graph cloning; non-call effect operands execute before their enclosing
  sequence event; receiver/option helper calls receive one exact callgraph edge;
  nested positive select-less sequences validate step one recursively; and
  traceable AST evidence supersedes coarse regex provenance in joined findings.
- Conflicting scalar matchers (two `name:` constraints on one node) now fail
  with a fix-it error suggesting `and:` branches.
- Restored deprecated evaluator-IR Go/JSON fields and SDK method signatures
  without restoring legacy WQL authoring. Compatibility constraints normalize
  on recursive deep copies before validation and at every exported evaluator
  entry point; active Rule-pointer cycles, nesting beyond depth 64, and
  conflicting values fail closed before later recursive walkers without
  mutating caller rules or templates.
- Exact contract/callee resolution now requires source/import provenance,
  precise call-site metadata, exact IDs, full selectors, and unambiguous legacy
  fallback. Interprocedural traversal carries exact caller metadata through
  nested overloads and follows recorded internal, inherited, self, super, and
  library calls while excluding member receivers from argument binding.
  Expression findings exclude statement semicolons, derived overrides suppress
  base SDK results, and extract MRO display entries no longer borrow shifted
  compact exact IDs.
- SDK: `ParseTemplate`/`LoadTemplate` accept only the canonical document shape;
  the exported evaluator IR gains `Template.Queries` and `Rule.ArgAny`;
  `ReachStep.File` and precise `NodeRef` spans are documented.

### Full correctness and release hardening

- Added immutable scan-local logging/options across the reader, builder,
  database loader, engine, template loader, and report generator. Deprecated
  package-global verbose wrappers remain only for exported SDK compatibility.
- Persisted sorted analysis-quality diagnostics through source builds and JSON
  cache loads. Every bundle writes `data/diagnostics.json`; manifests expose
  `analysisComplete` and per-severity diagnostic counts. `--strict-imports`
  applies the same fail-closed import policy to source scans, `--db` scans, and
  `build`, while the default remains tolerant.
- Canonicalized internal identities as `absPath#Contract` and
  `absPath#Contract.selector(types)`. Contracts/main-contract entries now carry
  exact `LinearizedBaseIDs`; call edges carry exact resolved contract IDs;
  identity-sensitive lookup rejects unresolved ambiguity instead of guessing.
- Hardened extract queries: exact contract/function IDs, selectors, 4-byte
  signatures, and unique names are supported; ambiguous input fails with sorted
  candidates.
- Reworked Foundry import resolution with real TOML parsing, active
  `FOUNDRY_PROFILE`, context-qualified/specificity-ordered remappings, fallback
  after missing targets, canonical import provenance, and sub-project boundaries.
- Hardened template archive installation with 64 MiB compressed, 8 MiB per-file,
  128 MiB decompressed, 4,096 accepted-file, and 8,192 ZIP-entry caps plus a
  rollback-safe staged directory swap.
- Corrected manifest scope/count semantics (`projectRoot`, `scanTarget`,
  compatibility `target`; contracts/interfaces/libraries/declarations) and
  indexed diagnostics plus optional HTML artifacts.
- Added fixed-clock report builders. Finding/content ordering is deterministic;
  real generated timestamps vary unless `GeneratorOptions.Now` /
  `BundleOptions.Now` supplies a fixed clock.
- Added reusable release gates for format/tidy/vet/staticcheck/gocyclo,
  Markdown links, normal/race/shuffled tests, host/ARM64 builds, govulncheck,
  official scan artifacts, and the competitive benchmark. The project uses
  `go.mod`'s Go version, raised to 1.26.5 because govulncheck found reachable
  standard-library advisories in older supported toolchains (fixes require
  >=1.25.12).
- Hardened the competitive benchmark (later relocated to `scripts/benchmark/`,
  see above). The multi-tool Docker image derives and verifies Go directly from
  `go.mod`, requested scanners fail closed, and output is confined to
  `benchmarks/results/`. The threshold checker enforces precision >= 65%,
  recall >= 95%, and zero failed cases from recomputed raw counts. The reviewed
  generated-lock hash for the pinned 4naly3er commit is built into the
  Dockerfile, so the canonical Compose command requires no external build
  argument.
- Template YAML is strictly `meta` plus `query:`; unknown keys are rejected
  at every level. The obsolete `templates/security/` lane was deleted; the
  retained inventory is 25 official + 5 feature-test + 76 benchmark = 106 WQL
  templates.

### Precise source locations (breaking output schema 2.0.0)

AST nodes and declarations now carry column and byte-offset ranges, not just
line numbers, closing the gap between "which line" and "which exact span" for
downstream tooling (editor jump-to, precise highlighting, diffing across
edits):

- **`StartCol`/`EndCol`/`StartByte`/`EndByte`** added to `types.ASTNode`,
  `Function`, `Modifier`, `Contract`, `StateVariable`, `Event`, `Struct`,
  `Enum`, and `Parameter` — one-based Unicode-code-point columns and zero-based,
  half-open UTF-8 byte offsets, zero for synthetic nodes with no source counterpart.
- **Interior AST nodes are now located, not just declaration roots.** Every
  statement/expression/assembly node built by `pkg/builder`'s AST builder
  passes through a dispatch chokepoint (`buildStatement`, `buildExpression`,
  `buildAssemblyOperation`, `buildAssemblyCall`, `buildInlineAssembly`, plus
  the `BuildFunctionAST`/`BuildModifierAST` roots) that stamps a real span via
  the new `pkg/builder/location.go` helpers (`spanFields`/`applySpan`).
- **Call sites carry a column and byte offset too:** `types.FunctionCall` and
  `types.CallEdge` gained `Col`/`Byte` alongside the existing `Line`.
- `StateWrite.Line` / `Guard.Line` (per-function effects facts) are now
  populated from the underlying AST node's `StartLine`.
- **Output schema bumped `1.0.0` → `2.0.0` (breaking):** consumers parsing
  `data/overview.json` / `data/findings.json` should check `schemaVersion`
  before assuming shape compatibility.
- Requires `github.com/th13vn/solast-go` **v0.1.7**, which added `Loc`/`Range`
  accessors on call/member/index postfix expressions.
- **Extension data layer:** `WriteBundle` now also emits `data/nav.json`
  (`report.BuildNavJSON` — navigable symbols, reverse call edges, and
  interface→implementation mappings) and `data/explorer.json`
  (`report.BuildExplorerJSON` — one entry per deployable contract with
  ordered constants/storage, entry functions, and getters), both carrying
  the precise `SrcRange` locations above. `data/manifest.json` indexes them
  under `files.data.nav` / `files.data.explorer`. See
  [`docs/extension-output.md`](docs/extension-output.md) for the schema.
- **WQL query language** (`select`/`from`/`where`, uniform matchers,
  intuitive-polarity presets) is the template syntax; all 106
  official/benchmark/feature-test templates use it. See
  [`docs/wql-syntax.md`](docs/wql-syntax.md).

#### Fixes

- **Deterministic finding output.** `ExecuteAll` now applies a total-order sort
  (`SortFindings`) before returning, so `findings.json`, `results.sarif`, and
  the per-group order in `findings.md` are byte-stable across runs. Previously
  findings were emitted in Go map-iteration order and shuffled every run.
- **Precise spans reach findings.** `Finding.Location` and `primaryAst` now
  carry the matched node's `col`/`endLine`/`endCol`/`startByte`/`endByte`, and
  SARIF declares `columnKind: unicodeCodePoints` and emits
  `startColumn`/`endColumn`/`endLine`. It deliberately omits
  `charOffset`/`charLength` because W3GoAudit offsets are UTF-8 bytes, not SARIF
  character offsets. Reachability steps carry a per-hop `file` so cross-contract
  SARIF traces point at the right file.
- **Same-name contract resolution.** Entry-function IDs, main-contract
  detection, source excerpts, call targets, extraction, and report consumers now
  carry exact source/contract/function identities. `Function.SourceFile`,
  `ResolvedContractID`, and `LinearizedBaseIDs` keep a mock and real contract
  with the same name separate; unresolved ambiguity is not repaired with a
  lexicographic or same-directory guess.
- **Reentrancy sequence FN.** A call used as an `if`-condition followed by a
  state write in the body is now matched by `sequence` rules (the condition and
  body were wrongly treated as mutually-exclusive arms).
- **WQL fail-open / dead paths closed.** A mixed context+AST `any:` and a
  multi-kind (list) `select:` are now rejected at load with actionable errors
  instead of silently over-matching / never matching.
- **Round-trip & robustness.** `DataFlowGraph` rebuilds its index after a `--db`
  round-trip; modifier ASTs are built with contract state-variable context;
  template download is size-capped and swapped in atomically; unresolved imports
  are surfaced instead of silently dropped; source excerpts handle block
  comments and word-boundary function matching; nav.json symbol IDs and ordering
  are collision-free. `--version` is wired and the CLI version is `0.4.0`.

### Standardized result-folder layout (output tree)

The result folder was reorganized from a flat pile (an all-contracts
`overview.md` dump plus one per-contract folder at the top level) into a
navigable, tool-conventional tree:

- **New root landing files:** `README.md` (counts + a Contents table linking
  every artifact) and `summary.md` (metrics + findings-by-severity + a rules-hit
  table sorted by severity then occurrence count).
- **`overview.md` is now an index, not a dump:** project metrics plus a
  one-row-per-contract table (entry-point / state-var / finding counts and a link
  into `contracts/`). The full per-contract detail moved into each contract's own
  `README.md`.
- **`corpus/` → `data/`**, and a new **`data/manifest.json`** machine index
  (tool, scope, counts, every artifact's relative path, and a `contracts[]` list)
  so a consumer discovers the whole folder from one file. A legacy `corpus/`
  folder from an older run is removed automatically.
- **Per-contract folders moved under `contracts/` and mirror source paths:**
  `contracts/<relative-source-path-without-ext>/<ContractName>/` with a new
  per-contract `README.md`, plus the existing `state-changes.md` and
  `workflows/`. Because the path encodes the source file, same-named contracts in
  different files no longer collide (no `Name__<filestem>` suffix). The
  `contracts/` tree is regenerated wholesale each run (idempotent; no stale
  folders).
- Reuse a pre-built DB via `--db data/database.json` (was `--db
  corpus/database.json`).

### Engine quality & correctness cleanups

Internal hardening from a self-review of the precision work (no template-syntax
changes):

- **Contract-scope related sites:** the synthetic `decl.contract` AST is now
  built **once** per contract and held in a single-slot memo; the match pass and
  `Finding.Related` enrichment share one tree instead of rebuilding it (bounded
  memory — a new contract evicts the previous, since each is visited once).
  Per-branch site collection now gathers *all* function sub-rules of a branch
  (`containedFunctionRules`), so an `any:` of several function shapes is faithful.
- **Single field-classification source of truth:** `presentRuleFields()` tags
  each Rule field `classAST` / `classContext` / `classDual`; `checkRule`,
  `ruleHasASTFields`, and `ruleHasContextFields` all read it (no more three
  hand-synced lists).
- **`unchecked_var`** now requires the bounding guard to use an **ordering**
  comparison (`<`/`<=`/`>`/`>=`), so `require(a != b); … a - b` is correctly
  flagged (was a false negative).
- **`attrInCSV`** requires the node to actually carry the attribute, so
  `mutability: nonpayable` in `match:` no longer spuriously matches attribute-less
  nodes.
- **Report extraction** anchors the function-start search to a word boundary
  (`function withdraw` no longer matches `withdrawAll`).
- Renamed the Go field `Rule.SourceRegex` → `Rule.Regex` to match the `regex:`
  keyword (no YAML change).

### WQL keyword simplification (historical)

Historical record. These evaluator-facing YAML keywords are not accepted by
the current loader; see `docs/wql-syntax.md` for the current syntax. The
change renamed:

- `source_regex:` → `regex:`
- `visibility_filter:` → `visibility:` and `mutability_filter:` → `mutability:`
  (one keyword each, valid in both `filter:` and `match:` — function precondition
  in filter, node-attribute match in match)
- `unguarded:` → `unchecked_var:`
- `not_bitwise_context:` (interim) → generic `statement_contains:` sub-rule

Docs (`docs/wql-syntax.md`) rewritten: implicit-AND emphasized (no need to wrap
sibling fields in `and:`), a complete Node Kinds reference (incl. the Declaration
group), and a fuller attributes table (`call_receiver`, `has_value`, `has_gas`,
`has_salt`, `call_option`, `parent`, …).

### Detector precision & access-control accuracy

False-positive reduction across the official pack, validated on a real on-chain
target (SpiceFiNFT4626) and the competitive benchmark.

#### Engine / access-control analysis

- **Privileged access control vs. item ownership are now distinguished.**
  `ownerOf(tokenId) == msg.sender` (a getter the caller indexes with a resource
  id of their own choosing) is item-ownership *self-scoping*, not a privileged
  gate — `getterIsResourceScoped`. It no longer counts toward `IsAccessControlled`
  (so `deposit`/`mint`-style functions are no longer mis-marked access-controlled)
  and instead feeds `ComparesCallerIdentity`.
- `ComparesCallerIdentity` is now **interprocedural**: it follows a `msg.sender`
  forwarded into a callee (`_withdraw(msg.sender, …)` → `ownerOf(id) != caller`).
  The `caller_checked` preset therefore treats item-ownership scoping as a valid
  mitigation (the ETH analogue of `require(from == msg.sender)`).
- Fixed `unwrapTypeCast` to unwrap only genuine type names (`address`, `uintN`, …)
  so a one-arg getter like `ownerOf(id)` is no longer mistaken for a cast.
- Fixed the interprocedural auth descent to resolve callees by bare name
  (`calleeNameMatches`) — previously it compared against the full selector and
  silently never matched.

#### New WQL predicates

- `unchecked_var` — on arithmetic `binary_op`, matches only when operands were not
  range-checked by a preceding `require`/`assert`/`if` guard.
- `statement_contains` — a generic statement-scoped sibling search (sub-rule
  matched against the node's nearest enclosing statement). The operator
  vocabulary lives in the template; used as `not: { statement_contains: … }` by
  incorrect-exp to exclude a `^` that shares a statement with another bitwise op.
- `label` — optional name on a `Rule.All` branch, surfaced in `Finding.Related`.

#### Builder

- A `0x…` number literal is now tagged `subtype: hex` (not `number`).

#### Official templates

- `arbitrary-send-eth` uses `not: { preset: caller_checked }` (clears owner-gated
  NFT-vault withdrawals while still flagging genuine arbitrary sends).
- `incorrect-exp`: flags `base ^ exp` / `2 ^ 8` / `10 ^ 18` (simple operands,
  `not_bitwise_context`); excludes OpenZeppelin `Math.average`/`mulDiv` and hex masks.
- `unchecked-arithmetic`: scoped to state-mutating functions and `unchecked_var`
  arithmetic; excludes pure library math and range-checked subtraction.

#### Benchmark

- Competitive corpus is now governed by the release quality gate above (TP 109 /
  FP 41 / FN 0); the previous 105/109, 60.0%-precision snapshot is retained only
  in repository history rather than documented as the current baseline.

## v0.3.1 - 2026-06-22

- Removed old benchmark results and scripts from the repository.
- Bumped CLI version to `0.3.1`.

## v0.3.0 - 2026-06-22

Compared with the previous `0.2.0` CLI version. This release changes the scan
experience from "print or write one report file" into an audit workspace that is
ready for humans, automation, and AI-assisted review.

### Scan Output And Report Workspace

- Default scans now write a result folder named after the scanned project, file,
  or database.
- The folder always includes `overview.md`, `findings.md`, `results.sarif`,
  `run.log`, and `corpus/{database.json,findings.json,overview.json}`.
- Each main contract gets its own folder with `state-changes.md` and one
  workflow file per entry function.
- HTML is now an optional mirror via `--html`; JSON and SARIF are always part of
  the result folder.

Mechanism: `report.WriteBundle` owns folder generation, while the CLI opens
`run.log` before scanning and routes all verbose package logs into it.

### Template Home And Updates

- Added `~/.w3goaudit/config.yml` and a managed template home at
  `~/.w3goaudit/templates`.
- First run attempts to download the latest `th13vn/w3goaudit-templates`
  release, with the embedded official pack kept as the offline fallback.
- Added `--update-templates` to refresh the template home and `--update` to
  self-update via `go install github.com/th13vn/w3goaudit/cmd/w3goaudit@latest`.

Mechanism: new `pkg/home` handles config loading, release lookup, zip download,
safe extraction, `.version` tracking, and fallback behavior.

### CLI UX Changes

- Bumped CLI version from `0.2.0` to `0.3.0`.
- Added short flags for common workflows: `-t`, `-o`, `-d`, `-v`, `-H`, `-q`,
  `-s`, `-m`, `-i`, `-e`, `-l`, `-T`, and `-u`.
- Added exact severity filtering with `--severity`; `--min-severity` remains a
  threshold filter, and the two are mutually exclusive.
- Console output is now title-only by default for large scans; full detail lives
  in the result folder or is shown with `--verbose`.
- Missing output directories are created automatically for build/report outputs.
- Unresolved inheritance references are surfaced after scans.

Compatibility note: the old direct format flags (`--json`, `--md`, `--sarif`)
were replaced by the result-folder model; use `--stdout` for console-only output
and `--html` for optional HTML files.

### Analysis Accuracy

- Added builder phase 7: per-function effects analysis for direct state writes,
  guards, branch conditions, modifiers, sender checks, and `tx.origin` usage.
- Access-control detection now separates privileged authorization from
  caller self-scoping. `require(from == msg.sender)` is not treated as owner or
  role access control.
- Added the property-true `caller_checked` preset for detectors where self-scoping is a valid
  mitigation, especially arbitrary `transferFrom`.
- `super` call resolution is now context-aware across all most-derived C3
  linearization leaves, avoiding reachability false negatives in cooperative
  multiple inheritance.
- Build output and report ordering are more deterministic.
- Tolerant parser recovery now logs warnings when recovered parse errors may
  have dropped contracts, functions, or state.

Mechanism: `types.SemanticFacts.FunctionEffects` stores the new effects, the
state matrix reads them through call-graph reachability, and the call graph adds
deduplicated context-specific `super` edges after the normal build.

### Detector Pack

- Reorganized `templates/official` into severity folders:
  `critical/`, `high/`, and `medium/`.
- Curated the embedded official pack to 25 production detectors, focused on
  critical/high/medium security signal and removing low/info noise.
- Detector IDs now use severity-prefixed names such as
  `CRITICAL-SELFDESTRUCT-UNPROTECTED`, `HIGH-ARBITRARY-TRANSFERFROM`, and
  `MEDIUM-UNCHECKED-SEND`.
- Added `templates/test/taint-probe-parameter.yaml` for focused taint testing.

### Reports And SARIF

- Overview reports now show each main contract's Solidity pragma version.
- State-change reports map state variables to direct writers and reachable entry
  points.
- Workflow files summarize signature, access control, guards, branch conditions,
  transitive state effects, and a call workflow.
- SARIF now uses the SchemaStore SARIF 2.1.0 schema URL.

### Benchmarks And Tests

- Added a self-contained `benchmarks/` suite comparing W3GoAudit against
  Slither, Semgrep Decurity rules, and 4naly3er-style detectors.
- Added benchmark corpora, fixtures, WQL template ports, and runner scripts.
- Added tests for result bundle creation, deterministic database builds,
  context-aware `super`, complex C3 inheritance, storage-anchored access control,
  effects extraction, and severity filtering.
- Added new Solidity fixtures for C3, `super`, mixed coding styles, access
  control, parser edge cases, and taint stress.

### Dependencies

- Updated `github.com/th13vn/solast-go` from `v0.1.4` to `v0.1.6`.
