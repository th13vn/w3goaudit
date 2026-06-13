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
- Linearized bases: `MyToken -> Pausable -> Ownable -> Context -> IERC20 -> IOwnable`
- Entry points: `totalSupply()`, `mint()`, `pause()`, `unpause()`

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
| Total Files | 6 |
| Total Contracts | ~14-17 |
| Interfaces | 4-5 |
| Libraries | 3-4 |
| Abstract Contracts | 4-5 |
| Main Contracts | 6-7 |
| Total Functions | ~55-65 |
| Entry Functions | ~22-32 |

---

## Validation Checklist

- [ ] All contract kinds correctly identified (interface, library, abstract, contract)
- [ ] Main contracts properly detected
- [ ] Function visibility correctly captured
- [ ] State mutability accurate
- [ ] Modifiers recorded
- [ ] Inheritance chain built correctly
- [ ] Call graph includes all call types
- [ ] Function signatures accurate for complex types
- [ ] Entry points correctly identified
- [ ] No crashes or errors during build
