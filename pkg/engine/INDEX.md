# pkg/engine - WQL Template Execution

## Purpose

Executes WQL templates against the contract database to find security vulnerabilities.

## WQL (template surface)

**A WQL document is meta plus one query: block.** The block holds
`select`/`from`/`where` or a one-level `and:`/`or:` query
composition; see [`docs/wql-syntax.md`](../../docs/wql-syntax.md) for the
full language reference. All 106 official/benchmark/feature-test templates in
this repo use it.

- `wql.go` — parses a WQL document (`TemplateDoc`) and **lowers** it to
  the evaluator `Template`/`Rule` IR below (`TemplateDoc.lower()`): simple
  queries via `SimpleQuery.lower()`; `and:` via `lowerAnd` (one QueryBlock
  whose match uses labeled `Rule.All` branches at the join scope —
  context matchers are rejected inside branches); `or:` via `lowerOr` (one
  QueryBlock per branch in `Template.Queries`, per-branch filters preserved,
  cross-scope branches allowed). The authoring surface never touches the
  evaluator (`verify.go`) — every template runs through
  `checkRule`/`Verify`/`finalizeTemplate` as compiled evaluator IR.
- `wql_catalog.go` — the exact name tables the lowering step consults:
  `blockKindToIR` (§5 block-kind aliases → `types.KindXxx`/semantic groups),
  and `attrNameToIR` (§7 attribute aliases → node-attribute keys). Preset names
  are already canonical evaluator values and are validated directly against
  `BuiltinPresets` during lowering and finalization.
- **Single strict loader:** `LoadTemplate`/`ParseTemplate`/
  `LoadTemplatesFromFS` all route through `parseTemplateDocument`. Unknown
  keys at every level (document, query, branch) are rejected by
  `yaml.Decoder.KnownFields(true)`; YAML merge keys (`<<`) are rejected
  recursively before presence inspection, and a missing `query:` fails with a
  pointed error. Query-key presence and node kind are recorded after strict decoding,
  so null/empty composition values cannot masquerade as absent keys; nested
  composition is rejected structurally (branches carry no and:/or: fields).
  Raw query nodes are validated before typed decoding: explicitly authored
  `select`/`from`/branch `label` values must be non-null, non-empty scalars and
  explicitly authored `where` values must be non-null, non-empty lists.
  Lowering also rejects empty matcher maps/lists, empty required matcher
  strings, `unchecked_var: false`, and signed/non-decimal `arg.N` keys. A
  simple query may omit both `select` and `from` when `where` supplies an
  actionable AST anchor; it defaults to `entry_function`. Context-only
  select-less `where` queries remain invalid because they cannot identify a
  reportable AST site.
- The exported `Template`/`QueryBlock`/`Rule` evaluator IR is not a YAML input
  schema. Direct `yaml.Unmarshal` into `Template` rejects with guidance to use
  `ParseTemplate`/`LoadTemplate`, preventing SDK callers from bypassing the
  strict loaders; programmatic IR construction and JSON behavior remain
  available.
- Parsed documents lower into the existing `Template`/`QueryBlock`/`Rule`
  evaluator IR, then run through the unchanged `finalizeTemplate`/
  `validateRulePlacement`/`validateKinds`/`validatePresets` pipeline.

## Key Files

### engine.go
Main query execution engine.

**Exports:**
- `Engine` struct - Holds database reference
- `New(db)` - Create an engine using deprecated package-global verbose logging
- `NewWithOptions(db, Options{Logger})` - Create a scan-local engine; a nil logger is disabled
- `Execute(template)` - Run one template. Single-query templates execute
  their one QueryBlock; or:-composed templates (`len(Queries) > 1`) execute
  every block via `executeQuery` and union the findings. The private matched-site
  identity deduplicates only the same precise AST/location site found by an
  earlier branch. Its file/span key carries an optional kind: an unknown kind
  is retained provisionally, then replaced and consumed when the first concrete
  kind arrives at the span. Unknown-first and unknown-last orders therefore
  produce the same concrete findings, while two different known kinds remain
  distinct. Identity is provenance-path-
  independent whether the span came from `PrimaryAST` or `Location`;
  duplicates inside one branch and findings without a precise span are retained
  in deterministic branch order
- `ExecuteAll(templates)` - Run multiple templates, then `SortFindings` for a
  deterministic total order (findings are otherwise collected in map-iteration
  order, which shuffled `findings.json`/`results.sarif` across runs)
- `SortFindings(findings)` - Total-order sort (file, line, col, primaryAst
  start, template, contract, function, …) making output byte-stable
- `Finding` struct - Vulnerability finding result (now carries optional
  `Reachability`, `PrimaryAST`, `EntryPoint`, and `Related` matched sites)
- `Location` struct - Finding location info; carries the matched node's precise
  span (`Col`/`EndLine`/`EndCol`/`StartByte`/`EndByte`) when Line anchors on
  that node. `ReachStep` carries a per-hop `File`.
- `RelatedLocation` struct - Additional exact matched source site for
  multi-condition findings, including label, file/contract/function,
  line/Unicode columns/UTF-8 bytes, and matched node kind/name
- `ReachabilityPath`, `ReachStep` - Call chain from entry to host of the
  dangerous statement
- `NodeRef` - Matched AST node identification (kind / name / range)
- `EntryRef` - Auditor-actionable fix-here pointer
- `LocationSource` (enum: `LocationSourceVerifier`, `LocationSourceMatchedNode`)
- `Engine.SetLocationSource(LocationSource)` - Override the location mode;
  the env var `WGAUDIT_LOCATION_FROM_MATCHED_NODE` still takes precedence
- `MaxRuleRecursionDepth` - Constant cap (64) on `Verify` recursion depth
- `MaxInterproceduralTaintDepth` - Constant cap (12) on recursive internal-call taint tracing
- `MaxTaintFixpointPasses` - Constant cap (8) on intra-function taint dataflow fixpoint iteration (`buildFunctionTaintEnv`)

**Thread-safety:** `Engine` is **NOT** safe for
concurrent use. `currentFunction`, `currentContract`, `currentSourceFile`,
and `recursionDepth` are mutated during a scan. SDK consumers that want
parallelism must allocate one `Engine` per goroutine. This contract is
documented inline at the struct definition.

**Execution Scopes:**
- `all_contract` - Every contract/interface/library
- `main_contract` - Only main deployable contracts
- `function` - All functions
- `entrypoint` - Public/external functions of main contracts (most common)
- `source` - Raw source-file regex checks for non-AST rules
- `contract` - Contract-type definitions only
- `library` - Library-type definitions only
- `abstract` - Abstract contract definitions only

Contract scopes (`all_contract`, `main_contract`, `contract`, `library`,
`abstract`) evaluate `match:` against a synthetic `decl.contract` AST. Its
root and declaration children copy the builder's exact source file, line,
Unicode-column, and UTF-8 byte spans. Active `decl.function` roots are selected
by canonical selector over `Database.LinearizedContracts`, so a derived
override replaces the inherited implementation while overloads remain
distinct. The tree also materializes inherited and local `decl.variable` and
`decl.modifier` nodes plus `decl.parameter` children tagged with
`parameter_role: input`, `return`, or `modifier`. Structural `contains` rules
can therefore span local and inherited declarations in one contract context
(for example: payable `msg.value` accounting plus inherited
`Multicall.multicall`). Each internal `Rule.All`
branch may carry an optional `label:` (a `Rule.Label` field, no matching
semantics) used to name its matched sites in `Finding.Related`; branches with no
label fall back to a positional `condition N` (`contractBranchLabel`). The
engine carries no per-detector label knowledge — naming lives in the template.

**Filter Support:**
- When `filter:` is present, evaluates those rules first
- Only functions/contracts passing the filter are then checked against `match:`
- Auto-separation: engine detects whether a `not:` rule is filter-level or AST-level; no manual split needed

**Context Management:**
- Stores `currentFunction` and `currentContract` for recursive call tracing
- Stores `currentTaintEnv` while matching so helper parameters can inherit the caller's actual argument sources
- Used by verify.go for advanced checks

**Location accuracy:**
- Function findings resolve source files from the exact `absPath#Contract.selector` function ID when scanning entrypoints, and from the loop contract when scanning all functions. This avoids duplicate contract names in different files corrupting benchmark labels and finding locations.
- Inherited entry matching keeps the derived contract as the verifier and
  callee-resolution context, while each reachability step takes its file from
  the exact function owner. Contract findings with a real primary node span
  anchor `Location` on that node and retain its exact host contract/function.
  A location-less primary match stays at the verified contract/file level and
  does not borrow an enclosing function or its declaration line.

**Matched-node attribution & Reachability (additive, opt-in default):**

Every `Finding` carries optional fields populated whenever the engine can
determine them; they are always emitted when present, regardless of the
location-source mode:

- `Finding.PrimaryAST` (`*NodeRef`) — the matched AST node's `kind` / `name` /
  `startLine`. This is the *dangerous statement* the rule was anchored on.
- `Finding.Reachability` (`*ReachabilityPath`) — ordered list of `ReachStep`s
  from an externally-callable entry function down to the function that hosts
  `PrimaryAST`. Single-step paths (the match happened in the entry directly)
  are still emitted so reports always have something to render.
- `Finding.EntryPoint` (`*EntryRef`) — the auditor-actionable fix-here function;
  today this is `Reachability.Steps[0]` (the entry). When the semantic
  access-control analyzer ships, it becomes the highest hop with a
  sub-Verified `AuthVerdict`.
- `Finding.Related` (`[]RelatedLocation`) — all contributing sites for
  multi-condition contract-scope findings. For example, a single contract-level
  issue can list both `depositETH` and `mintETH` payable `msg.value` entrypoints
  plus the inherited `Multicall.multicall` batch function.

**Location provenance switch:**

The engine supports two location-derivation modes via `LocationSource`:

- `LocationSourceVerifier` *(default)* — preserves today's behavior:
  `Location.Function` / `Location.Contract` come from the verifier-function
  context (typically the entrypoint that started the match), `Location.Line`
  comes from the matched node when available. Backward-compatible for every
  existing JSON / SARIF / report consumer.
- `LocationSourceMatchedNode` — every field of `Location` comes from the
  matched AST node's enclosing function/modifier. Aligns w3goaudit's
  attribution with SARIF / Slither / Semgrep conventions (report at the
  dangerous statement, carry the entry hop in `EntryPoint`).

The switch is opt-in:

- Env var: `WGAUDIT_LOCATION_FROM_MATCHED_NODE=1` (also accepts `true` /
  `matched`).
- API: `Engine.SetLocationSource(LocationSourceMatchedNode)`. The env var
  takes precedence over the API setting so CI/scripts can flip the mode
  without touching code.

**How the capture works (internal):**

- `Engine.match *matchTrace` — set to a fresh struct by `executeOnEntryFunctions`
  and contract-scope execution before each match attempt; cleared after. Records
  `Primary` (the first committed atomic match) and `Chain` (the call chain that
  reached `Primary`).
- `Verify` populates `e.match.Primary` when `matchAtomic` returns true AND the
  current rule has at least one surface predicate (`hasAtomicPredicate`).
  This means logical containers (`any:`/`contains:`/`sequence:` wrappers)
  don't capture themselves — only the leaf predicate they anchor on does.
  Captures are transactional: if later constraints on the same branch fail
  (`args`, `left`/`right`, `all`, `contains`, etc.), `Primary` is rolled back
  so reports point at the node that actually satisfied the rule.
- `verifyAtFunctionWithCallees` extends the call chain as it recurses into
  internal callees; on the first successful match, the chain is stashed into
  `e.match.Chain`. Interprocedural `sequenceEvent` values carry their own exact
  `ipPath`, so repeated occurrences of one reused callee AST pointer cannot
  overwrite each other's reachability.
- `buildLocation` and `enrichFindingFromTrace` consume the trace at the
  `executeOn*` boundary to produce the final `Location` (mode-dependent) plus
  the optional fields. Matched-node mode always uses `Primary` for line,
  columns, and bytes; host identity prefers the final `Chain`/
  `ChainContracts` hop, then the enclosing declaration, then verifier
  fallbacks. `hostFunctionFor` walks the matched node's parent chain, preserves
  exact `contract` and `source_file` attributes from any declaration kind, and
  adds a function name only for `decl.function` or `decl.modifier`. An inherited
  `decl.variable` finding therefore uses its base contract/file and keeps the
  function field empty without replacing the real primary line.
- Interprocedural visit keys, host source lookup, synthetic contract ASTs, and
  internal-callee MRO scans use `Function.SourceFile` plus
  `Database.LinearizedContracts`. A qualified function ID that misses never
  falls back to another same-named contract; name-only lookup remains only for
  legacy unqualified IDs/caches.
- `extends` remains a regex over `Contract.LinearizedBases` display names. It
  does not dereference identities, so standalone SDK/manual values and legacy
  caches without materialized base objects continue to work.
- `matchFunctionWithTrace` / `matchContractWithTrace` isolate provenance capture
  with defer-based restoration for every executor. Function joins re-evaluate
  each labeled top-level `Rule.All` branch against the same function, contract,
  taint environment, and callee-following mode. `buildContractLocation` and
  `enrichContractRelatedLocations` handle every contract-kind scope, anchoring
  a real-span primary location on the actual matched node, leaving a
  location-less primary at contract/file scope, and recording each branch
  trace's actual matched node rather than substituting its enclosing function.
  A contract-root branch retains an empty function name but emits the exact
  contract declaration line, Unicode-column, and UTF-8 byte span. Identical
  query branches on that declaration therefore share one precise union
  identity. Only truly location-less synthetic nodes remain coarse.
  Reachability file attribution prefers `Function.SourceFile`, while the
  derived/deployment contract remains available in the verifier chain for MRO
  and internal-callee resolution. The synthetic `decl.contract` AST is built
  **once** per contract and held in a single-slot memo
  (`Engine.contractASTContract`/`contractASTRoot`, reset each `Execute`; a new
  contract evicts the previous one — bounded memory since each contract is
  visited once), so the match pass (`verifyAtContract`) and the related-site
  enrichment share one tree — no rebuild. Applied `guarded_by` lookup uses a
  separate single-slot memo
  (`Engine.modifierDeclContract`/`modifierDeclByName`) that clones only exact-MRO
  modifier declarations, keeps the first derived-first definition per name,
  and never materializes unrelated function bodies or variables. Switching
  contracts evicts the prior bounded map, and each `Execute` resets both memo
  families. Per-branch site collection uses
  `containedFunctionRules` (all function sub-rules of a branch, so `any:` of
  several function shapes is faithful), re-matched against each `decl.function`
  node of the shared tree.

### verbose.go
Deprecated compatibility logging infrastructure.

**Exports:**
- `VerboseEnabled` - Global flag to enable/disable verbose logging
- `VerboseLog(format, args...)` - Conditional verbose logging function
- `SetVerboseWriter(w io.Writer)` - Set custom output writer for verbose logs (default: os.Stdout)

Engine execution uses its object-local logger, including verifier recursion and
preset diagnostics. Directory and embedded template loading use
`TemplateLoadOptions.Logger`; nil retains the legacy logging behavior for old
callers. The compatibility writer is mutex-serialized.

**Output Prefix:** None (clean output)

**What it logs:**
- Template loading: `✓ Loaded template: <id> (<path>)`; lenient loading also logs `⚠️  Skipping invalid template <path>: <error>`
- Template execution (start and completion)
- Number of templates being executed
- Findings count per template
- Total findings across all templates

**Output Configuration:**
- Default: Writes to stdout
- File output: Use `SetVerboseWriter()` to redirect to a file

---

### semantic_model.go
Internal value, provenance, operation, and access-path primitives for the
program-point semantic analyzer. These types stay private to `pkg/engine` and
do not add fields to the serialized database, findings, reports, or exported
SDK surface.

- `controlState` records unknown, fixed, restricted, derived, or controlled
  values. `joinControlState` preserves a state only when both CFG inputs agree;
  mixed proven states join to unknown instead of fabricating strict control.
- `accessPath` identifies a root symbol plus typed field, tuple, index, mapping,
  or memory-offset segments. `Key` uses a versioned, length-prefixed encoding
  for arbitrary string fields and explicit numeric boundaries, so delimiters
  inside RefIDs, names, mapping keys, or alias sets cannot collide.
- `semanticRef` ties a value or operation to its exact function, contract,
  source file, AST node, and operation index.
- `semanticValue.Clone` preserves scalar, type, and AST provenance values while
  defensively copying the primary path, source paths, and every segment slice.
- `normalizeAccessPaths` returns caller-independent paths sorted by stable key
  with duplicates removed, without reordering or aliasing the input. It
  canonicalizes every zero-length segment slice to nil before keying and
  deduplication, so equivalent nil and empty paths normalize identically in
  either input order.
- `semanticOp` and `semanticFunction` provide the internal operation stream and
  AST-node index used by later analyzer tasks.

### semantic_analysis.go and semantic_lower.go

The scan-local internal analyzer lowers each exact Solidity or Yul function AST
into a stable semantic operation stream. A function identity exists only when
canonical selector text is present. The owner must be the exact current
database contract for `SourceFile#ContractName`, and a supplied runtime contract
must have a canonical ID and be the exact current database object. Operation
file provenance comes from the defining owner while `ContractID` comes from the
runtime contract. Missing, malformed, foreign, or ambiguous identities fail
closed without entering the lowering cache.

- Identifier roots use `ASTNode.RefID` when present. Member paths recurse only
  through the base child. Index expressions never become part of the base path.
- Array fixed indexes use canonical numeric identities. Dynamic indexes use a
  versioned SHA-256 alias derived from normalized expression structure only
  after recursively proving every identifier root exact. Mapping keys and Yul
  storage/memory offsets use the same validation. Direct `msg` and `tx` roots
  are environment identities only for non-assembly Solidity identifiers with
  no local/state/parameter kind; malformed or shadowed names fail closed.
  Mapping-key segments remain distinct from array-index segments, including
  typed non-numeric literal keys.
- Tuple values use deterministic temporary roots with exact positional lanes.
  Tuple roots require a valid positive `tuple_arity`, and every populated child
  requires a unique integral `tuple_index` in range. Missing, malformed,
  negative, duplicate, fractional-cache, or out-of-range metadata produces an
  unknown operation and durable diagnostic. Return and other value contexts
  retain populated tuple lanes, including holes, instead of collapsing them.
  Lane sources point to real child paths, while assignment writes contain only
  real LHS paths. Tuple destructuring is detected from strict arity/index facts,
  not populated-child count, so a single populated LHS among holes still emits
  one exact write paired with the matching RHS lane. Multi-LHS assignments emit
  one ordered operation per populated lane, preserving holes and reversed
  target names without set-normalizing the correspondence. Every operation
  value consumer uses status-returning tuple lowering; malformed nested tuple
  metadata preserves child effects, records one diagnostic, and replaces the
  enclosing concrete operation with unknown instead of dropping the input.
  Tuple roots include source spans or deterministic AST occurrence paths for
  location-less nodes.
- Casts are transparent wrappers rather than calls. Calls, checks, returns,
  delete, increment, decrement, storage mutations, sload/sstore, and generic
  Yul operations retain exact provenance. Memory opcodes expose deterministic
  offset paths without attempting Task 8 memory-region reconstruction. The
  canonical Solidity `this` value may remain an exact source value inside a
  cast even though it does not gain an access path or dynamic-alias identity.
- `semanticFunction.ByNode` maps each exact AST pointer to every emitted
  operation index in deterministic order. Unsupported semantic shapes emit one
  `semanticOpUnknown` and one deduplicated
  `analysis.semantic_unsupported` diagnostic. Structural wrappers do not emit
  unsupported diagnostics.
- Builder metadata and RefIDs are serialized AST facts, and tests pin identical
  access-path keys and operation provenance after database JSON round-trips.
- Lowering caches use exact owner-function plus runtime-contract identity.
  Persistent Yul slots are runtime-contract scoped, while memory offsets remain
  function scoped. Constant slots compare equal across functions and dynamic
  slots retain exact parameter/local RefIDs.
- Nested effects use one deterministic postorder traversal. Calls in index
  bases/keys and nested unary mutations emit exactly once before their enclosing
  effect.
- Missing RefIDs, tuple metadata, LHS counts, or representable lvalue structure
  fail closed with unknown operations and site-specific diagnostics. Only direct
  canonical `msg` and `tx` environment roots bypass RefID requirements.
- Numeric fixed paths use a Solidity-aware exact rational parser for decimal,
  hexadecimal, exponent, fraction, underscore, and time/currency unit syntax.
  Underscores are accepted only between component digits, exponent work is
  bounded before power allocation, and results above `uint256` fail closed.
  Only non-negative integral values in the Yul-word/index domain become fixed
  paths.
- Solidity revert/selfdestruct and Yul revert/return/selfdestruct/stop/invalid
  lower as terminal operations; require/assert remain checks.
- Cached semantic functions and every returned path/value are deeply cloned.
  Unsupported diagnostics include exact byte sites or deterministic AST
  occurrence paths for location-less nodes. Deduplication covers every
  serialized diagnostic field, including severity, import path, and incomplete
  state. Source/cache fingerprints start with exact defining-function and
  runtime-contract identity, then cover operations, values, ByNode,
  diagnostics, tuple pairing, and occurrence identity, including inherited
  zero-operation functions.

---

### wql.go
WQL parser + lowering to evaluator `Rule` IR. See
"WQL (template surface)" section above and
[`docs/wql-syntax.md`](../../docs/wql-syntax.md).

**Exports / key pieces:**
- `TemplateDoc`, `QueryDoc`, `QueryBranch` - the document shape: meta plus a
  `query:` that is a simple select/from/where map or a one-level `and:`/`or:`
  list of branches
- `Matcher` - one `where` matcher; values retain raw `yaml.Node` for
  recursive forms
- `SimpleQuery` - internal simple-query lowering unit (no longer a YAML target)
- `parseWQL(raw)` - strictly decode into `TemplateDoc`, rejecting unknown
  fields at every struct level while matcher maps remain dynamically validated;
  after decoding, reject YAML merge keys anywhere in the document and capture
  query-key presence plus composition node kinds for fail-closed shape dispatch
- `(*TemplateDoc).lower()` - dispatches simple/`and:`/`or:` lowering with the
  presence-sensitive shape rules (exclusive non-null list forms, ≥2 branches,
  and: needs a structural join `from:`, or: branches reject `label:`)
- `lowerAnd`/`lowerBranchRule` - and: branches lower to labeled `Contains`
  rules ANDed at the join scope; context-level matchers, absence-only branches,
  and regex-only branches without traceable AST evidence are load errors
- `lowerOr` - or: branches lower to one QueryBlock each (`Template.Queries`).
  A branch with no branch/query `from` and no `select` may still author an
  actionable `where`; it defaults to `entry_function` through
  `SimpleQuery.lower`. Context-only where branches reach `buildMatch` and are
  rejected for lacking an AST anchor, while a truly empty branch is rejected
  before lowering.
- `(*SimpleQuery).lower()` - the simple-query → evaluator-IR algorithm: resolves `from` to a
  `Scope`, resolves the scalar `select` block kind via `blockKindToIR`, lowers every
  `where` matcher into an AST-layer (`Match`) and/or context-layer
  (`Filter`) `Rule` fragment and merges them (`mergeRuleInto`), then
  assembles the final `Match` (`buildMatch`) — a list `select` is rejected while
  decoding; a scalar `select` wraps `where` in `Contains` unless `where` centers
  on `sequence:`, which stays top-level and must use the same first-step anchor;
  every positive-polarity sequence inside a select-less match requires its
  first step to guarantee positive actionable evidence, recursively through
  logic/traversal/operand/argument containers; negative-polarity sequences under
  `not:` remain valid refinement evidence;
  `scope: source` requires a bare top-level `regex:`.
- `mergeRuleInto()` delegates repeated sibling negations to `mergeNotInto()`,
  which keeps the first negation in `Rule.Not` and appends later sibling
  negations as `Rule.All` branches instead of merging their children into
  `not (A and B)`.
- `lowerKeyValue(key, val)` - thin grouped dispatch point for every matcher key.
  Private helpers lower string, attribute, nested-rule, list (`and:` is the
  explicit conjunction), negation, preset, and dynamic (`arg.N`/`arg.any`/
  bare attribute) categories independently, keeping the WQL surface and error
  messages unchanged while avoiding one monolithic switch.

### wql_catalog.go
The WQL block-kind and attribute name tables — every name here is verified
against the underlying engine (`types.KindXxx`/`KnownSemanticGroups` and node
attribute keys), so the authoring surface introduces **zero new matching
semantics**, only aliases.

**Exports:**
- `blockKindToIR(name) (string, bool)` - §5 block-kind catalog
- `attrNameToIR(name) (string, bool)` - §7 attribute catalog (excludes
  `name`/`visibility`/`mutability`/`tainted`, which are dedicated `Rule`
  fields, not `Attr` map entries)

---

### template.go
WQL template loading plus the evaluator IR that documents lower into.
`Template.Queries []QueryBlock` (additive JSON `queries`) carries every
executable block of an or:-composed template (`Queries[0] == Query`; empty
for single-query templates); `finalizeTemplateWithLogger` validates/
normalizes every block via `finalizeQueryBlock`.

**Exports:**
- `Template` struct - Compiled evaluator IR returned by the loader; not a public YAML schema
- `TemplateMeta` struct - Template metadata
- `TemplateLoadOptions` - Directory loading policy (`IgnoreInvalid`) plus a scan-local `Logger`
- `QueryBlock` struct - Evaluator scope/filter/match IR produced by lowering
- `Rule` struct - Recursive evaluator IR; public YAML authors use WQL matchers instead
- `Scope` type - Scope constants
- `parseTemplateDocument(data, source, logger)` - Single strict loader path;
  parses the WQL document (unknown top-level keys rejected), lowers to IR, and
  finalizes validation/normalization
- `LoadTemplate(path)` - Load one WQL YAML file through the shared path
- `LoadTemplates(dir)` - Load all templates from directory recursively, fail-closed on invalid/incomplete templates or zero valid templates
- `LoadTemplatesWithOptions(dir, opts)` - Optional lenient loading (`IgnoreInvalid: true`)
- `LoadTemplatesLenient(dir)` - Convenience wrapper for old skip-invalid behavior in ad-hoc tooling
- `ParseTemplate(yaml)` - Parse WQL from a string through the shared path
- `MatchesRegex(pattern, value)` - Regex helper

**Evaluator IR structure (not accepted as public YAML):**
```yaml
meta:
  id, title, severity, confidence, description, recommendation
query:
  scope
  filter:     # function/contract-level preconditions (optional)
  match:      # AST pattern matching
```

**Rule Fields (Default logic is AND if multiple fields are set):**
- **Logic:** `all`, `any`, `not`, `sequence`. Repeated sibling public `not:`
  matchers lower as independent conjuncts: `(not A) and (not B)`.
- **Atomic:** `kind`, `name`, `attr` (+ inline `is_state_var`, `operator`, `visibility`, `mutability`)
- **`unchecked_var`:** for unsigned `left - right` / `left -= right`, matches
  unless exact stable operand expressions are locally proven as
  `left >= right`. Accepted proofs are an immediately preceding
  `require`/`assert`, a dominating safe `if` arm whose subtraction is the first
  executable operation through `stmt.block`/`stmt.unchecked` wrappers, or
  fallthrough after the unsafe arm unconditionally exits with an absent or
  effect-free surviving arm. The first non-proving prior sibling, including an
  assignment, declaration, emit, internal call, or external call, ends the
  proof. Before any proof is accepted, the complete guard condition and every
  additional `require`/`assert` argument must be structurally effect-free, and
  `subtractionExpressionPathIsEffectFree` validates the complete path to the
  enclosing sequential statement. It allowlists pure expression wrappers and
  simple return/assignment statements only when every sibling is structurally
  effect-free; call ancestors, assignment-expression siblings, creation,
  increment/decrement, delete, unknown wrappers, reversed/unrelated
  inequalities, non-terminating branches, unstable operands, and signed
  subtraction fail closed. Implemented by `operandsGuardedBefore` and its
  expression/topology helpers in verify.go.
- **`statement_contains`:** sub-rule matched against the node's nearest enclosing statement (closest `stmt.*`/`check.*`/`decl.variable` ancestor). Statement-scoped sibling search — narrower than `inside`, wider than `contains`. Generic: the match vocabulary lives in the sub-rule, not the engine. Pair with `not:` for "no such node in this statement" (e.g. incorrect-exp excludes a `^` whose statement holds another bitwise op). Placement validation recurses through its body at the current AST layer, so context-only predicates cannot hide inside it. Implemented by `statementContains` in verify.go; wired through `normalizeRule`/`walkRules`.
- **Source:** `regex` as a scope-aware raw-text predicate
- **Traversal:** `contains`, `inside`
- **Filter (function-level preconditions):**
  - `modifier` — regex match on function modifiers
  - `extends` — regex match on inherited contracts
  - `func_name` — regex match on function name
  - `visibility` — comma-separated: `public,external,internal,private`
  - `mutability` — comma-separated: `payable,view,pure,nonpayable`
  - `has_guard` — rule: function body must contain a matching guard
  - `version` — Solidity version constraint
  - `preset` — built-in preset check
  - `has_param` — function has parameter by name
- **Call:** `args: {N: Rule}` or `arg.N:` flat keys (equivalent); `arg_any`
  (`arg.any:`) matches when SOME positional argument satisfies the sub-rule
  (receivers/call options excluded, evaluated by `matchArgAny` in verify.go).
  Repeated sibling `arg.any:` predicates remain separate existential checks,
  so each may be witnessed by a different positional argument; put a `Rule.All`
  inside one `arg.any:` when one argument must satisfy several constraints.
- **Taint:** `tainted_from`
- **Binary:** `left`, `right`

**Argument Matching Notations (equivalent):**
- `args: { 0: ..., 1: ... }`
- `arg.0: ...`, `arg.1: ...`

**Template Validation:**
- `LoadTemplate()` / `ParseTemplate()` require `meta.id` and `meta.severity`
  and reject malformed YAML or invalid WQL before execution.
- `LoadTemplates()` is fail-closed: one invalid template in the directory
  aborts the load, and a directory with zero valid templates errors. Use
  `LoadTemplatesWithOptions(dir, TemplateLoadOptions{IgnoreInvalid: true})`
  or `LoadTemplatesLenient()` only when skipping invalid files is intentional.
- `validateRulePlacement()` rejects AST-level fields inside `filter:` and filter-level fields inside `match:` with a precise error. Field classification lives in **one** table — `presentRuleFields()` tags each field `classAST` / `classContext` / `classDual` — and is the single source of truth shared by `checkRule`, `ruleHasASTFields`, and `ruleHasContextFields`, so adding a field means editing one place. Dual fields (`regex`, `visibility`, `mutability`) are valid in both layers.
- `validateRegexes()` compiles every regex pattern at load time and
  rejects invalid patterns immediately. A bad regex never silently falls
  back to case-insensitive substring matching.
- `validatePresets()` rejects any `preset:` name that isn't in
  `BuiltinPresets`. A typo like `preset: unAuthenticatd` errors at load
  with the list of known presets.
- `validateKinds()` rejects any `kind:` value that isn't a registered AST
  kind (see `types.allRegisteredKinds`), a known semantic group
  (`types.KnownSemanticGroups`), a single-segment prefix
  (`call`, `check`, `stmt`, `expr`, `decl`, `asm`), or a **multi-segment prefix**
  of a registered kind (`call.lowlevel`, `call.builtin`). `IsKnownKind` and
  `matchKind` accept the same prefix forms. Typos like `kind: outgoing_calls`
  (plural) or `kind: ".*"` error at load with the list of acceptable forms.
- `validateScope()` rejects an unknown `scope:` (e.g. `functions`); an empty
  scope is allowed and defaults to `entrypoint`. Previously an unknown scope
  silently fell through to entrypoint, changing what code was scanned.
- `validateRuleValues()` rejects out-of-vocabulary `tainted_from`
  (`parameter`/`state_var`/`local_var`/`sender`/`user_controlled`),
  `visibility`, `mutability`, and malformed `version:` constraints.
  Comma-separated visibility and mutability filters must contain at least one
  non-empty recognized token, so comma-only values are rejected.
- `finalizeTemplate()` also rejects an out-of-enum `severity:` (must be
  CRITICAL/HIGH/MEDIUM/LOW/INFO — otherwise the finding vanishes from the
  Markdown/HTML reports) and a `scope: source` template that lacks a top-level
  `match.regex` or carries a `filter:`. Contract scopes now support AST
  traversal through the synthetic `decl.contract` root, so `contains` / `all` /
  `any` are valid there.
- All of the recursive validators share one `walkRules` visitor, so a new Rule
  field is validated in one place instead of N hand-rolled walkers that drift.
- The same pipeline is shared by `LoadTemplate` (files), `ParseTemplate`
  (inline/SDK), and `LoadTemplatesFromFS` (embedded `fs.FS` packs).
- Invalid templates abort by default; lenient mode logs skipped files under `--verbose`.

**Normalization:**
- `normalizeQueryBlock()` — recurses into filter/match and normalizes rules
- `normalizeRule()` — promotes inline attrs (is_state_var, operator, visibility,
  mutability) into the Attr map so the matcher reads them uniformly
- `prepareRuleForEvaluation()` deep-copies and normalizes one caller-owned
  programmatic `Rule`, then applies the same regex, preset, kind, taint-source,
  visibility, mutability, and version validators used by template loading.
  `Engine.preparedRule()` routes every exported evaluator entry point through
  that shared preparation and fails closed without mutating the caller.
- Compatibility cloning tracks active nested `Attr` map/slice identities,
  including containers authored through exported `Rule.IsStateVar`, and
  counts them against `MaxRuleRecursionDepth`; cycles and depth 65 fail closed,
  while depth 64 and shared DAG containers remain valid and caller-owned values
  are not mutated.
- WQL's matcher-node lowering compiles dynamic `arg.N` keys directly into
  `Rule.Args` at every nesting level; finalization no longer traverses raw YAML.

**Regex performance & safety:**
- `compileRegexCached(pattern)` memoizes compiled regexes in a process-wide
  `sync.Map`. A pattern referenced from N AST nodes is now compiled once,
  not N times.
- `MatchesRegex(pattern, value)` uses the cache and returns false on
  invalid patterns (load-time validation should have caught those).

---

### verify.go
WQL rule verification logic (THE CORE).

**Main Function:**
- `Verify(node, rule)` - Recursive rule matching, depth-bounded by
  `MaxRuleRecursionDepth = 64`. Compatibility copying first tracks active
  source Rule pointers and the same depth across pointer, slice, and `Args` map
  shapes, so cycles and over-depth graphs fail closed before recursive
  normalization or evaluation can overflow the Go stack. The exported call
  prepares and validates the rule once; private recursive verification receives
  the already prepared copy.

**Logic Operators:**
- `verifyAll()` - AND logic (all sub-rules must match)
- `verifyAny()` - OR logic (at least one must match)
- `verifySeq()` - Sequence matching (ordered descendants, non-contiguous) over
  an execution-event partial order shared with interprocedural matching.
  Receiver, call-option, explicit-argument, assignment operand/value, return,
  emit, and similar effect-input subtrees precede the enclosing effect event;
  the call precedes an inlined callee; distinct pre-effect sibling subtrees are
  unordered and may satisfy either relative sequence order. Ordinary sibling
  statements retain source order. Regex-only root capture is lower priority
  than successful traceable AST evidence, so regex refinement cannot steal
  Primary/Related provenance. `sameExecutionPath()` rejects pairs
  that first diverge into mutually-exclusive arms of a common control structure,
  via `areExclusiveArms()`:
  - `stmt.if` — `then` vs `else` (the condition expression stays sequential);
  - `expr.conditional` — the two ternary arms (`conditional_part` true/false);
  - `stmt.try_catch` — the success body vs any catch clause, and two distinct
    catch clauses (`try_part` body/catch:N); the always-executing try expression
    (`try_part = expr`) co-executes with whichever arm fires and is never
    exclusive.

  This kills cross-branch and cross-try/catch false positives (e.g. an
  `outgoing_call` in a try body never forms a CEI sequence with a `state_write`
  in a catch). Each event also carries accumulated conditional-arm tokens for
  its caller and every inlined callee occurrence; conflicting tokens reject
  cross-tree pairs where lowest-common-ancestor checks cannot apply. Each
  function expansion also has a distinct AST occurrence identity, so raw
  subtree ancestry and `sameExecutionPath` constrain only events from the same
  expansion; events from repeated expansions of one reused AST rely on their
  partial-order edges and occurrence-specific arm tokens. This is **not a full
  CFG** – loops are still treated as straight-line, there is no dominance /
  reachability reasoning (a `return`/`revert` between two nodes does not break
  the sequence).
  Candidate primary provenance is transactional: subtree exclusions, path
  incompatibility, and failed suffixes restore the checkpoint, while only a
  complete suffix commits its first-step anchor.
- Negation via `not`

**Traversal Operators:**
- `verifyHas()` / `contains` - Search descendants (depth-first, first match)
- `verifyInside()` / `inside` - Search ancestors

**Atomic Matchers:**
- `matchAtomic()` - Check kind, name, attr on node
- `attr` also sees semantic type facts mirrored by the builder, including
  `type_kind`, `receiver_type`, `receiver_type_kind`, and
  `receiver_type_is_address`. The additive `receiver_name` attribute belongs
  to the selected call node and names only its direct tagged receiver child,
  so nested receivers in arguments or call options cannot satisfy it. Matching
  legacy schema-2.0.0 caches derives the same value from the immediate
  `call_receiver` child when the copied attribute is absent, without mutating
  the AST.
- `matchArgs()` - Validate function call arguments
  - Skips metadata children tagged `call_receiver` or `call_option`, so `args.0`
    stays the first Solidity argument even though receivers and call options are
    preserved in the AST for taint-aware templates.
  - Rejects negative programmatic indexes defensively; authored `arg.N` keys
    accept decimal digits only.
- `checkTaint()` - Track expression sources
  (`parameter`/`state_var`/`local_var`/caller identity) with context-sensitive
  overrides for internal helper calls. `user_controlled` matches either a
  parameter or caller identity (`msg.sender`, `tx.origin`, exact zero-argument
  internal `_msgSender()` confirmed by call metadata and MRO resolution when
  available). Same-named identifiers, state/local/parameter names,
  external/self calls, unresolved calls, and nonzero overloads retain ordinary provenance. A
  member-access identity must have the direct identifier receiver `msg` or
  `tx`; chained values such as `account.msg.sender` do not qualify. Indexed
  arguments like `from[i]` inherit the base expression's taint.
- Interprocedural taint follows entrypoint → internal helper calls. For
  example, `_deposit(from, amount)` maps the callee's `from` parameter to
  `parameter`, while `_deposit(msg.sender, amount)` maps it to sender identity
  and does not satisfy `tainted_from: parameter`.
- Simple local aliases are propagated in the active function environment, so
  `address payer = from; _deposit(payer, amount)` remains parameter-tainted.
- `buildFunctionTaintEnv()` builds that environment as a **bounded dataflow
  fixpoint** (`MaxTaintFixpointPasses = 8`), not a single forward pass. Variable
  declarations with initializers participate (the builder lowers them to
  `stmt.assign`), and carrying the environment across passes lets a later
  definition feed an earlier use — loop-carried taint and out-of-source-order
  aliases converge (see `TestTaintFixpointPropagatesLoopCarriedAlias`). Updates
  remain **strong** (each assignment overwrites its target), so reassignment to
  a sender identity still kills parameter taint and the context-sensitive
  precision is preserved. It is flow-sensitive over straight-line code and
  fixpoint-convergent over loops, but still **not path-sensitive**: it does not
  track which branch a definition came from, and taint does not yet flow out
  through a callee's return value.

**Filter Helpers:**
- `checkFunctionContext()` - Check modifiers, inheritance, func_name, visibility, mutability, has_guard
- Context predicates are decomposed into private helpers for regex-list,
  comma-separated enum, parameter, guard, `all`, and `any` matching. The public
  verification flow and context/AST split are unchanged.
- `hasMatchingGuard(fn, contract, rule)` - Match inline check nodes or an exact
  applied modifier declaration resolved through the contract's exact MRO.
  Context verification temporarily disables provenance capture so a matching
  guard cannot replace the selected dangerous statement.
- `VerifyAtFunction()` - Entry point for function-scope verification
  (auto-separates filter vs AST checks)
- `VerifyAtFunctionWithCallees()` - Entry-point match helper that follows internal calls with context-sensitive argument taint
- `VerifyAtContract()` - Entry point for contract-scope verification

All four exported evaluator entry points (`Verify`, `VerifyAtFunction`,
`VerifyAtFunctionWithCallees`, and `VerifyAtContract`) use the same direct-rule
preparation pipeline. Invalid regexes, kinds, presets, taint sources,
visibility values, mutability values, and version constraints return `false`;
recursive/internal evaluation reuses the prepared rule instead of preparing at
each node or callee.

**Kind Matching (`matchKind`):**

| Kind / Group | Matches |
|---|---|
| `outgoing_call` | All external calls + asm.call/delegatecall/staticcall |
| `eth_transfer` | transfer/send/call/asm.call |
| `delegatecall` | lowlevel delegatecall + asm.delegatecall |
| `check` | check.require, check.assert, check.revert |
| `guard` | Alias for `check` |
| `guard.require` | Alias for `check.require` |
| `guard.assert` | Alias for `check.assert` |
| `guard.revert` | Alias for `check.revert` |
| `token_call` | Evaluator-only compatibility group for `call.external`; public WQL uses `external_call` plus `name:` |
| `state_write` | `stmt.assign` with `is_state_var=true`; `stmt.state_mutation` whose tagged receiver has a state lvalue root; unary `delete`/`++`/`--` whose operand has a state lvalue root; and `asm.sstore` |
| `state_read` | expr.identifier (state_var) + asm.sload |
| `any_call` | All Solidity call kinds (no asm), including `call.builtin.selfdestruct` |
| `selfdestruct` | `asm.selfdestruct` + `call.builtin.selfdestruct` (Solidity-level `selfdestruct(addr)` and `suicide(addr)`) |
| Prefix match | `call` → all `call.*`, `asm` → all `asm.*`, etc. |
| `guard.*` prefix | Remapped to `check.*` |

For mutation and unary nodes, lvalue-root matching follows only an identifier
or the base/receiver chain of index/member access. It never scans index
expressions or arbitrary descendants, so `tmp[stateIndex]++` remains local.

**Source regex:** `regex` is scope-aware. With `scope: source` it scans
each raw source file; with contract/function scopes it checks the current
contract/function snippet; inside AST matching it checks the node source range
when line data is available. Use it for exact syntax that is not represented
well in the AST, not as a replacement for context, taint, or call matching.

**Filter Predicates in `checkFunctionContext()`:**

| Field | Effect |
|---|---|
| `func_name: REGEX` | Filter by function name regex |
| `visibility: a,b` | Filter by comma-separated visibility values |
| `mutability: a,b` | Filter by comma-separated mutability values |
| `has_guard: {rule}` | An inline check node or applied modifier declaration in the function's exact guard context must match the rule. |

**`IsContextOnly()`:**  
Returns `true` if a rule contains ONLY filter-level fields (modifier, extends, version, preset, func_name, visibility, mutability, has_guard, has_param, regex) and NO AST-level fields (kind, name, contains, etc.).

**Binary Matching:**
- Handles `left`/`right` for member_access, assignment, binary_op
- Member-access `left:` evaluates every non-name predicate against the
  receiver child and applies `name:` to the receiver name separately.
  Member-access `right:` supports only `name:` because the member identifier
  has no child node; every other predicate fails closed.
  A successful name-only member-side match captures the enclosing
  `expr.member_access` as primary evidence when no deeper primary exists.

---

### presets.go
Built-in preset checks for common patterns.

**Exports:**
- `PresetFunc` type - Function signature for presets
- `BuiltinPresets` map - Registry of preset functions
- `IsKnownPreset(name)` - Used by template load to reject typos

**Built-in presets:**
- `access_controlled` — `Function.IsAccessControlled(db)`. True when the
  function has privileged access control through owner/admin/role modifiers,
  auth helpers, or caller-vs-storage / caller-vs-hardcoded-address guards.
- `caller_checked` — `IsAccessControlled(db) ||
  Function.ComparesCallerIdentity(db)`. True when the function is privileged
  or self-scopes the caller, including item-ownership checks such as
  `ownerOf(tokenId) == msg.sender` and forwarded equivalents.
- `reentrancy_guarded` — true when the function has a recognized
  reentrancy-guard modifier.

Every preset returns true when its named safety property is present. Express
the vulnerable absence with normal negation:

```yaml
where:
  - not: {preset: reentrancy_guarded}
```

**Unknown presets are rejected at load**: a typo like
`preset: unAuthenticatd` previously matched every function silently
(scan-time fallback was `true`). It now errors at load with the list of
known presets, and the runtime fallback returns `false`.

**Available Presets:**

#### access_controlled
Returns true when privileged access control is present. Checks in order:
1. Auth modifier regex: `(?i)(onlyOwner|onlyAdmin|onlyOperator|onlyRole|onlyGuardian|onlyGovernor|onlyGovernance|onlyGov|onlyManager|onlyController|auth|authorized|requiresAuth|onlyMinter|onlyPauser)`
2. Internal auth call heuristic: calls matching `(?i)(_?check|_?require|_?verify|_?validate|_?enforce).(Owner|Auth|Admin|Role|Sender|Access|Permission)`
3. AST check: `msg.sender`/`tx.origin`/`_msgSender()` compared against owner/admin patterns
4. Recursive check: walks internal/inherited/self/super call chain into base contracts

#### caller_checked
Returns true when the function has either privileged access control or a
caller self-scoping check. It includes binding a
sensitive argument to `msg.sender` (`require(from == msg.sender)`) or
restricting the caller to a resource they own (`ownerOf(tokenId) == msg.sender`,
including the interprocedural forwarded `_withdraw(msg.sender,…)` form). Use for
detectors where self-scoping is a valid mitigation, such as arbitrary
`transferFrom` and arbitrary-send-eth.

#### reentrancy_guarded
Returns true when the function has a reentrancy guard.

Modifier regex (single source of truth — all reentrancy templates route
through this preset to prevent regex drift across the corpus):
`(?i)(nonReentrant|noReentrancy|lock|locked|guard|mutex|reentrancyGuard)`

---

## Test Inventory

Deprecated programmatic/JSON `Rule.SourceRegex`, `VisibilityFilter`, and
`MutabilityFilter` normalize on a recursive deep copy at every exported
evaluator entry point and template execution path. Active pointer cycles and
nesting beyond `MaxRuleRecursionDepth` fail closed before later walkers;
conflicts fail closed, caller-owned rules are unchanged, and WQL YAML exposes
no alias mapping. Internal-callee metadata matches byte,
then line plus column, then one physical same-name line site. Traversal passes
the caller function explicitly at every depth and follows Solidity `call.*`
nodes only for recorded internal, inherited, self, super, or library calls.
Member receivers and call options are excluded from parameter binding. Resolved
calls use exact IDs/selectors; legacy name/arity fallback is restricted to
genuine `call.internal` nodes and must identify one distinct runtime-MRO
selector.

- `verify_test.go`, `sequence_path_test.go`, `statement_contains_test.go` —
  atomic/logic/traversal matching, transactional primary-node capture,
  partial-order call sequence rules, branch-arm constraints,
  statement-scoped matching, args, taint, and golden
  evaluator behavior.
- `validation_test.go`, `public_yaml_test.go`, `template_pack_test.go` — WQL
  acceptance, unknown-key rejection through both loader and public SDK
  boundaries, evaluator-IR JSON compatibility, value/regex/version validation,
  embedded-FS loading, canonical active-vocabulary checks, and the exact
  25-official + 5-test + 76-benchmark = 106 repository inventory.
- `wql_test.go`, `wql_lower_test.go`, `wql_catalog_test.go`,
  `wql_execute_test.go` — strict scalar decoding, catalog mappings, lowering
  into evaluator IR, select-absent root matching, sequence-anchor conflict
  handling, and end-to-end WQL execution.
- `wql_strictness_test.go` — authored null/empty query fields, non-vacuous
  nested matchers, the complete null/empty select/from/where/label matrix for
  both `and:` and `or:` branches, decimal-only argument indexes, and the
  negative-index panic regression.
- `provenance_regression_test.go` — provenance-independent union identity,
  three-branch unknown/concrete order normalization, exact matched-node
  host/span attribution, transactional sequence anchors, name-only member
  evidence, and contract-root related-site fallback.
- `contract_declaration_test.go` - exact synthetic declaration materialization,
  six-field declaration and parameter spans, parameter roles, exact-MRO
  overload/diamond/special-function selection, inherited variable finding and
  related-site ownership, cross-file OR identity, applied-modifier memo reuse,
  eviction/rebuild/reset behavior, modifier-only lookup without contract-AST
  construction, inherited/overridden/location-less modifier guards, and inline
  versus applied `guarded_by` behavior.
- `wql_composition_test.go` includes exact contract-root union deduplication and
  exact contract declaration primary/related spans while keeping the function
  field empty.
- `wql_improvements_test.go`, `audit_fixes_test.go` — semantic groups, context
  predicates, contract-scope inherited ASTs, fail-closed directories, mixed-layer
  rejection, precise locations, and deterministic findings.
- `interprocedural_taint_test.go`, `arbitrary_send_eth_test.go` — helper-call
  taint bindings/fixpoints, reentrancy sequences, type-cast exclusions, exact
  source attribution, and forwarded ownership guards.
- `state_write_test.go` - state assignments, direct storage-array `push`/`pop`,
  indexed `delete`, state `++`/`--`, assembly `sstore`, and fail-closed local
  unary-operation coverage for the `state_write` semantic group, including a
  state variable used only as the index of a local mutated lvalue and
  same-named storage-array/scalar function parameters that shadow state,
  lexical-scope restoration, and inherited direct/indexed storage mutations.
- `semantic_model_test.go` - collision-safe and stable access-path identity,
  strict control-state joins, defensive semantic-value cloning, and sorted,
  deduplicated normalization without caller-input mutation.
- `semantic_lower_test.go`, `semantic_test_helpers_test.go` - exact struct,
  tuple, fixed/dynamic index, mapping, storage, call/cast, unary mutation, Yul
  lexical and memory-operation lowering; deterministic ByNode provenance;
  unsupported-diagnostic deduplication; source/cache parity; and the existing
  `Diverge_StructFieldFP` field-sensitivity regression.
- `user_controlled_templates_test.go` — end-to-end caller-identity and parameter
  taint behavior for the eight widened official/benchmark templates, including
  fixed/state-target and access-controlled safe controls plus representative
  retained parameter-only detectors.
- `benchmark_regression_test.go` — named competitive regressions and duplicate
  contract identity isolation.
- `benchmark_template_precision_test.go` – actual repository-template
  regressions for repeated initializer and callback negations, contract-scope
  provenance, and guard-aware binary/assignment subtraction, backed by real
  benchmark and official Solidity fixtures with vulnerable and safe controls.
- `db_roundtrip_test.go`, `source_roundtrip_test.go` — cached-database finding
  parity and persisted source content.
- `logging_test.go` — scan-local engine/template-loader logger isolation.

---

## Execution Flow

```
Template → validateRulePlacement() → normalizeQueryBlock() → Engine → Scope Selection → checkFunctionContext() → Verify AST Rules → Generate Findings
```

**For each scope item:**
1. Check filter (modifier, extends, func_name, visibility, mutability, has_guard, has_param, regex, presets, version)
2. Verify AST rules in `match:` (kind, name, contains, sequence, etc.)
3. If match, create Finding with location

---

## Integration Points

**Input:** `*types.Database` from builder  
**Input:** `*Template` from LoadTemplate  
**Output:** `[]*Finding` with severity, location, description

---

## Design Notes

- **Recursive verification** allows complex nested rules
- **Taint analysis** tracks where identifiers come from
- **Recursive call tracing** finds external calls through internal call chains
- **Filter-aware** auto-separates function-level vs AST-level checks
- **Preset system** provides reusable common checks
- **Performance** uses early exits and visited sets to prevent infinite loops
- **Binary matching** supports left/right for complex expression matching
- **Normalization** happens at template load time and once at each direct SDK
  evaluator boundary; recursive evaluation reuses the prepared copy
- **Silent failures fixed** — invalid templates now emit warnings under `--verbose`
