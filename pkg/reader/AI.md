# pkg/reader – source discovery

Discovers Solidity files, loads source bytes, detects project roots, resolves
imports and remappings, records git metadata, and exposes occurrence-aligned
import provenance to the builder.

## Key files

| File | Responsibility |
|---|---|
| reader.go | Reader lifecycle and source loading |
| project.go | Foundry, Hardhat, and Truffle root detection |
| imports.go | Import parsing and occurrence bindings |
| remappings.go | Foundry remapping resolution |
| resolver.go | Filesystem and suffix fallback resolution |
| fallback.go | Last-resort source matching |
| git.go | Repository metadata and links |
| verbose.go | Compatibility logging wrappers |

## Invariants

- Only Solidity files inside the selected scope are loaded. Directory discovery
  skips build/dependency/test/certora folders and Foundry `*.t.sol`/`*.s.sol` files; an
  explicitly named file is always read.
- Resolution checks explicit mappings, node_modules/lib/root paths, then unique
  suffix fallbacks.
- A fallback is accepted only for an existing in-scope file and never for an
  ambiguous match.
- Raw/canonical paths, aliases, and unit aliases remain occurrence-aligned and
  survive database caching.
- Unresolved imports become diagnostics. --strict-imports fails closed in source
  and cache modes.
- Scan-local logging is injected; global verbose state is compatibility-only.

## Change checklist

Update reader tests and docs/usage.md for resolution behavior. If provenance,
diagnostics, or source identity changes, update builder/types indexes and run
source/cache parity plus full gates.
