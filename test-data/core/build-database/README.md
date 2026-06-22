# Database Building Test Suite

## Overview

This test suite validates the W3GoAudit database builder with focused, simple test contracts.

## Test Files

### 01-basic-contracts.sol
**Purpose:** Test basic contract types and function visibility

**Tests:**
- Interface detection (`IToken`)
- Library detection (`MathLib`)
- Abstract contract detection (`Ownable`)
- Main contract detection (`BasicToken`)
- Function visibility: `external`, `public`, `internal`, `private`
- Function types: `view`, `pure`, regular
- Entry point identification (public/external functions)

**Expected Results:**
- 1 Interface, 1 Library, 1 Abstract, 1 Main Contract
- BasicToken has 4 entry points: `mint()`, `transfer()`, `balanceOf()`, `calculate()`

---

### 02-inheritance.sol
**Purpose:** Test inheritance and C3 linearization

**Tests:**
- Multiple inheritance (`MyToken` inherits from `Pausable` and `Ownable`)
- Diamond pattern (both inherit from `Context`)
- Interface implementation
- C3 linearization order

**Expected Results:**
- Main Contract: `MyToken`
- Linearized bases (derived-first, verified against solc 0.8.20 — the last-listed
  base is most derived): `MyToken -> IOwnable -> IERC20 -> Ownable -> Pausable -> Context`
- Entry points (state-mutating only): `mint()`, `pause()`, `unpause()`
  (`totalSupply()` is `view`, so it is not an entry function)

---

### 03-function-calls.sol
**Purpose:** Test call graph building

**Tests:**
- Internal function calls
- External calls via interface
- Library calls
- Low-level calls (`.call`, `.delegatecall`, `.staticcall`)
- Self-calls (`this.function()`)
- Payable functions

**Expected Results:**
- Call graph tracks all call types
- `processDeposit()` -> `_validateAmount()`, `_transferToVault()`, `_updateState()`
- Library calls to `MathLib.add()`
- External calls to `IVault.deposit()`

---

### 04-complex-types.sol
**Purpose:** Test function signature generation with complex types

**Tests:**
- Simple types (address, uint256, bool)
- Arrays (dynamic and fixed-size)
- Structs (simple and nested)
- Mappings
- Tuple returns
- Bytes types

**Expected Results:**
- Accurate signatures for all parameter combinations
- Struct types properly resolved
- Array dimensions preserved
- Named returns captured

---

### 05-state-modifiers.sol
**Purpose:** Test state mutability and modifiers

**Tests:**
- State mutability: default, `view`, `pure`, `payable`
- Custom modifiers: `onlyOwner`, `nonReentrant`, `validAmount`
- Multiple modifiers on single function
- Virtual and override functions

**Expected Results:**
- Correct mutability classification
- Modifier names captured
- Virtual/override flags set
- Inherited functions tracked

---

### 06-extract-involve.sol
**Purpose:** Fixture for the `extract involve` / `extract inheritance` subcommands

**Tests:**
- Transitive workflow discovery from an internal helper to its entrypoints
- `extract inheritance` accepting a main contract and rejecting a library
- Library calls preserved across an `abstract → concrete` inheritance chain

**Contract shape:**
- `Math` (library) — `clamp(v, max)`
- `VaultBase` (abstract) — `_clamp(v)` calls `Math.clamp`
- `VaultV1` (main, inherits `VaultBase`) — entries `deposit()` and `withdraw()` both call `_settle()`, which calls `_clamp()`

**Expected Results:**
- `extract involve _settle` → 2 workflows (`deposit`, `withdraw`)
- `extract involve _clamp` → 2 workflows (transitively, via `_settle`)
- `extract inheritance VaultV1` → succeeds
- `extract inheritance Math` → fails (library, not deployable)

---

### 07-diamond.sol
**Purpose:** Classic A/B/C/D diamond pinned to solc 0.8.20

**Expected Results:**
- `D` C3 linearization (derived-first): `D -> C -> B -> A`

---

### 08-semantic-types.sol
**Purpose:** Pin the receiver-type-driven semantic classification of one-argument
calls, where the call kind cannot be decided from the call site alone and depends
on the resolved type of the receiver.

**Contract shape:** `IOneArgToken` (interface with `transfer(address)` /
`send(address)`); `SemanticTypeFacts` holding an `IOneArgToken` state var and an
`address payable` state var.

**Expected Results:**
- `interfaceTransfer` / `interfaceSend` — receiver is an interface, so a
  one-arg `transfer`/`send` classifies as `call.external` (NOT a builtin)
- `localCastTransfer` — same, where the interface receiver is a local cast
  (`IOneArgToken(token)`)
- `payableTransfer` — receiver is `address payable`, so `.transfer(amount)`
  classifies as `call.builtin.transfer`
- `payableCastTransfer` — `payable(to).transfer(amount)` is also
  `call.builtin.transfer` because `payable(...)` yields `address payable`

---

### 09-statements.sol
**Purpose:** Builder coverage for statement / expression forms that were
previously dropped or misclassified, so calls and state writes inside them still
reach the call graph and AST.

**Contract shape:** `ICallee` (interface); `Deployed` (constructed via `new`);
`StatementForms` with a custom `error`, an auth helper `_enforceOwner()`, and a
non-auth-named `gate()` modifier that calls the helper.

**Covers:**
- `revert` statements in both forms — string `revert("...")` and custom-error
  `revert Unauthorized(to)` → `check.revert`
- `unchecked { ... }` blocks — calls inside still reach the call graph
- `do/while` loops → `stmt.loop` (`loop_type=do_while`)
- `try`/`catch` success body — calls inside still reach the call graph
- assembly assignment `ok := delegatecall(...)` (no `let`) → `asm.delegatecall`
  visited
- compound assignments (`&=`, `|=`, `%=`) and tuple assignment `(a, b) = (b, a)`
  → `stmt.assign` / state writes / `expr.tuple` targets
- `new Deployed(v)` → `call.create` edge
- modifier body calling an auth helper → `Modifier.Calls` populated (drives
  `IsAccessControlled` via `gate()`)

---

### 10-override-state-order.sol
**Purpose:** Asymmetric diamond that pins the three inheritance properties
auditors rely on, all verified against solc 0.8.20. Drives
`TestComplexDiamondOverrideAndStateOrder`.

**Contract shape:** `Base`; `Left is Base`; `Right is Base`;
`Middle is Left, Right`; `Derived is Middle`.

**Expected Results:**
- **C3 linearization** (derived-first): `Derived -> Middle -> Right -> Left -> Base`
- **State-variable storage order** (most-base contract first):
  `Base.baseVar`, `Base.baseFlag`, `Left.leftVar`, `Right.rightVar`,
  `Middle.middleVar`, `Derived.derivedVar`
- **Override binding along the MRO:** `super.foo()` → `Middle.foo`;
  `bar()` → `Right.bar` (overridden only on the Right branch);
  `baz()` → `Base.baz` (never overridden)

---

### 11-c3-classic-kz.sol
**Purpose:** The canonical Dylan / CPython C3 linearization example encoded as
real Solidity source. Exercises the FULL `c3Linearize` pipeline (base-list
reversal + canonical forward-order merge) end-to-end, not just the `c3Merge`
primitive that `TestC3MergeCanonicalClassicExample` pins in isolation. Drives
`TestC3ClassicKZEndToEnd`.

**Contract shape:** `O`; `A..E is O`; `K1 is C,B,A`; `K2 is E,B,D`; `K3 is A,D`;
`Z is K3,K2,K1`. (Solidity lists bases most-base-first, i.e. the reverse of
Python's argument order.)

**Expected Results (canonical C3, derived-first):**
- `L[K1] = [K1, A, B, C, O]`
- `L[K2] = [K2, D, B, E, O]`
- `L[K3] = [K3, D, A, O]`
- `L[Z]  = [Z, K1, K2, K3, D, A, B, C, E, O]`

---

### 12-super-chain.sol
**Purpose:** Cooperative multiple inheritance with a chained `super` call (the
OpenZeppelin `_update` pattern). Pins **leaf-context `super` resolution**: `super`
binds against the linearization of the MOST-DERIVED contract being instantiated,
not the contract where the call textually lives. Drives
`TestSuperChainContextSensitivity`.

**Contract shape:** `Root`; `StepA is Root`; `StepB is Root`;
`Full is StepA, StepB`. Every contract overrides `step()` and calls `super.step()`.

**Expected Results:**
- `Full` MRO (derived-first): `Full -> StepB -> StepA -> Root`
- `super` edges are the **sound union** over all instantiation contexts:
  - `Full.step -> StepB.step`
  - `StepB.step -> StepA.step` (Full's context — the previously-missing edge)
  - `StepB.step -> Root.step` (StepB standalone context)
  - `StepA.step -> Root.step`
- Consequence: `StepA.step` is reachable from `Full`'s entry via the super chain.

---

### 13-coding-styles.sol
**Purpose:** Mixed real-world coding styles the builder must parse without losing
the base list, override targets, or state-variable order. Drives
`TestCodingStylesParsing`.

**Covers:**
- Constructor-argument inheritance `is Priced(100)` — base NAME extracted as
  `Priced`, the `(100)` argument ignored
- Interface inheriting multiple interfaces (`ICombined is IRoot, IExtra`)
- Abstract contract in the middle of the chain (`Pricing`)
- Explicit multi-target override `override(Base, Middle)`
- State variables spread across the whole chain

**Expected Results:**
- `Vault` MRO (derived-first): `Vault -> Middle -> Priced -> Pricing -> Storage -> Base`
- `Vault.BaseContracts = [Priced, Middle]` (constructor args stripped)
- `ICombined` MRO: `ICombined -> IExtra -> IRoot`
- Storage-variable layout (most-base first): `Base.baseSlot`,
  `Storage.storageSlot`, `Storage.balances`, `Pricing.priceSlot`,
  `Priced.fixedPrice`, `Middle.middleSlot`, `Vault.vaultSlot`

---

### 14-super-multi-leaf.sol
**Purpose:** The definitive "super across multiple classes" case — a single shared
mixin `M` is pulled into TWO distinct concrete leaves, and `M.f()`'s `super`
target differs per leaf. A context-free call graph cannot encode that with one
edge, so the sound union must hold every per-leaf target *exactly*. Drives
`TestSuperSharedMixinMultipleLeaves`.

**Contract shape:** `Root`; `A is Root`; `B is Root`; `M is Root` (all call
`super.f()`); `LeafX is A, M`; `LeafY is B, M`.

**Expected Results:**
- `LeafX` MRO: `LeafX -> M -> A -> Root`; `LeafY` MRO: `LeafY -> M -> B -> Root`
- `M.f` carries THREE super edges: `-> A.f` (LeafX context), `-> B.f` (LeafY
  context), `-> Root.f` (M standalone) — the sound union, no spurious extras
- Full super edge set (exactly 7): `LeafX.f->M.f`, `LeafY.f->M.f`, `M.f->A.f`,
  `M.f->B.f`, `M.f->Root.f`, `A.f->Root.f`, `B.f->Root.f`

---

### 15-access-control.sol
**Purpose:** Validate the storage-anchored caller-guard rule in
`Function.IsAccessControlled`. A caller-identity comparison counts as access
control only when the other operand is NOT caller-controlled; comparing against a
function argument is self-authorization, not a privileged gate. Drives
`TestIsAccessControlledStorageAnchored`.

**Contract shape:** `AccessControlChecks` with paired access-controlled and
permissionless functions.

**Expected Results:**
- Access controlled (storage-anchored / hardcoded authority): `setOwnerState`
  (state var), `acceptOwnership` (state var), `adminOnly` (immutable),
  `treasuryOnly` (constant), `hardcodedGate` (literal address), `operatorOnly`
  (state mapping), `localFromState` (local aliased from state)
- NOT access controlled (caller-controlled / permissionless): `selfAuthParam`
  and `selfAuthParam2` (`from`/`to` are arguments), `localFromParam` (local
  aliased from an argument), `permissionless` (no caller check)

---

## Running Tests

### Build Database
```bash
./w3goaudit build test-data/core/build-database/ -o test-db.json
```

### Verify Results
```bash
# Check statistics
cat test-db.json | jq '.mainContracts | length'  # Should be 5-6

# Check contract types
cat test-db.json | jq '.contracts | to_entries[] | select(.value.kind == "interface") | .key'

# Check entry functions
cat test-db.json | jq '.contracts["path#ContractName"].functions[] | select(.visibility == "external" or .visibility == "public") | .name'
```

### Generate Summary
```bash
./w3goaudit test-data/core/build-database/ --md -o build-test-summary.md
```

---

## Expected Statistics

| Metric | Expected Value |
|--------|---------------|
| Total Files | 15 |
| Total Contracts | ~51 |
| Interfaces | ~9 |
| Libraries | ~3 |
| Main Contracts | ~15 |
| Total Functions | ~120 |
| Entry Functions | ~45 |

---

## Validation Checklist

- [ ] All contract kinds correctly identified (interface, library, abstract, contract)
- [ ] Main contracts properly detected
- [ ] Function visibility correctly captured
- [ ] State mutability accurate
- [ ] Modifiers recorded
- [ ] Inheritance chain built correctly (C3, incl. complex/diamond — 07, 10, 11, 13)
- [ ] State-variable storage order = reverse MRO (most-base first — 10, 13)
- [ ] `super` resolves to the sound union over all instantiation leaves (12)
- [ ] Call graph includes all call types
- [ ] Function signatures accurate for complex types
- [ ] Entry points correctly identified
- [ ] No crashes or errors during build
