# pkg/reader - Source File Reading

## Purpose

Discovers and loads Solidity source files from the filesystem with intelligent project detection.

## Key Files

### reader.go
Main file reader implementation.

**Exports:**
- `Reader` struct - Manages file reading state
- `New()` - Creates a reader using the deprecated package-global verbose configuration
- `NewWithOptions(Options{Logger})` - Creates a scan-local reader; a nil logger is disabled
- `Read(path)` - Auto-detect file or directory and read
- `ReadFile(path)` - Read single .sol file
- `ReadFiles(paths)` - Read multiple files
- `ReadDirectory(path)` - Recursively read directory
- `Diagnostics()` - Return a normalized defensive copy of durable reader diagnostics

**Auto-excluded directories:**
- `node_modules`, `out`, `artifacts`, `cache`, `test`, `lib`, `mocks`, `broadcast`, etc.

**Returns:** `[]*types.SourceFile` with:
- File path (absolute)
- File content (string)
- Content Checksum (SHA256)
- Canonical resolved-import provenance (`ResolvedImports`) after
  `ResolveImports`, including relative and remapped targets
- Per-occurrence structured import provenance (`ImportBindings`) containing the
  raw import path and canonical resolved file; builder parsing later enriches
  the same occurrence with unit and named-symbol aliases
- Contracts list (populated by builder)
- Imports list (populated by builder)
- Pragma version (populated by builder) - **Used for version checking**

**Import Resolution:**
- `ResolveImports(projectRoot)` - Recursively load imported files
- Uses `Resolver` to map import paths via remappings
- Import discovery uses a lightweight Solidity-aware lexer/parser
  (`imports.go`), not source-wide regular expressions. It recognizes direct,
  path-alias, namespace, named-symbol, and legacy alias directives across
  lines/comments while ignoring import-shaped text inside line comments,
  block comments, and ordinary string literals.
- Only loads files that are actually imported
- Prevents duplicate loading with `loadedPaths` tracking (keyed by canonical path)
- Records every successfully resolved canonical target on the importing
  `SourceFile.ResolvedImports`, even when the target was already loaded. This
  survives database JSON round-trips and lets identity resolution prefer the
  file that was actually imported over an unrelated same-directory duplicate.
- Records every valid authored import occurrence in `SourceFile.ImportBindings`
  without path deduplication. Repeated imports from one file remain distinct so
  different aliases survive into the builder and database cache.
- Handles transitive dependencies automatically
- **Unresolved imports are surfaced, not swallowed.** Each import that fails to
  load is recorded as a `types.Diagnostic` with code `import.unresolved`, reader
  phase, source file/import path, and `Incomplete: true`. `Diagnostics()`
  returns deduplicated, deterministically sorted records for injection into the
  builder/database. `UnresolvedImports() []UnresolvedImport` remains as a
  compatibility view over the same durable records. The CLI (`buildDatabase`)
  still prints a stderr warning summarizing them so incomplete analysis cannot
  masquerade as a clean scan. Complements builder diagnostics for unresolved
  base contracts.

**Git detection (`git.go`):**
- `parseGitBranch` handles a **detached HEAD** (raw 40-hex SHA in `.git/HEAD`)
  by returning the SHA, so blob links pin to the commit instead of falling back
  to a wrong `main`. Remote-URL parsing accepts both `url = X` and `url=X`.

**Path canonicalization:**
- `canonicalPath(path)` resolves symlinks (`filepath.EvalSymlinks`) and
  collapses `..`/`.` segments (`filepath.Clean`) before producing the cache
  key. Without this, `./contracts/A.sol` and `contracts/sub/../A.sol` would
  load the same file twice and corrupt the Database with duplicate contracts.
- `stripBOM(content)` removes leading UTF-8 BOM bytes so pragma/import
  regexes (which anchor at start-of-file) work on BOM-prefixed sources.
- `GetAllSources()` now returns a defensive copy — callers can't mutate
  the reader's internal slice.

### verbose.go
Deprecated compatibility logging infrastructure.

**Exports:**
- `VerboseEnabled` - Global flag to enable/disable verbose logging
- `VerboseLog(format, args...)` - Conditional verbose logging function
- `SetVerboseWriter(w io.Writer)` - Set custom output writer for verbose logs (default: os.Stdout)

`SetVerboseWriter` and `VerboseLog` serialize access to the legacy writer. New
scan pipelines inject `*logging.Logger` with `NewWithOptions`; the same logger
is forwarded to the nested `Resolver`, including sub-project remapping loads.

**Output Prefix:** None (clean output)

**What it logs:**
- File reading operations with byte counts
- Directory scanning progress
- Skipped directories
- Auto-detection of files vs directories

**Output Configuration:**
- Default: Writes to stdout
- File output: Use `SetVerboseWriter()` to redirect to a file

### project.go
Project framework detection.

**Exports:**
- `DetectProjectRoot(path)` - Find project root by looking for config files
- `DetectFramework(root)` - Identify Foundry/Hardhat/Truffle

**Detection Logic:**
- Foundry: `foundry.toml`
- Hardhat: `hardhat.config.js` or `hardhat.config.ts`
- Truffle: `truffle-config.js`

### resolver.go
Import path resolution with remapping support.

**Purpose:** Resolve Solidity imports to actual file paths
- Handle relative imports (./file.sol, ../file.sol)
- Handle npm/node_modules and `lib/` imports
- Support remappings from `remappings.txt` **and** the `remappings = [...]`
  array inside `foundry.toml` (the latter is what modern Foundry repos use when
  `auto_detect_remappings = false` and there is no `remappings.txt`)
- `foundry.toml` is parsed as TOML rather than searched with regular
  expressions. Only the active `FOUNDRY_PROFILE` is used (`default` when
  unset); a profile that omits `remappings` inherits the default/root value,
  while an explicit empty array disables inherited remappings. Comments and
  inactive profiles never become resolver input.
- Soldeer/other dependency managers work only via the remappings.txt they
  generate — there is no dedicated `dependencies/` directory fallback.

**Monorepo / multi-root resolution (sub-projects):**
- The scan root (passed to `NewResolver`) is often a git root that contains
  *several independent* Foundry/Hardhat projects (e.g. `packages/eip-*/`), each
  with its **own** `foundry.toml`, its **own** remappings, and its **own**
  `lib/` directory.
- `Resolve(importPath, fromFile)` therefore resolves each import against the
  **nearest enclosing sub-project** of `fromFile`, not the scan root.
  `findSubRoot` walks up from the file to the closest ancestor carrying a
  project config (`foundry.toml`/`remappings.txt`/`hardhat.config.*`/
  `truffle-config.js`), bounded by the scan root; if none is found the scan
  root itself is used. It canonicalizes symlinks through the nearest existing
  ancestor and verifies containment before inspecting any directory, so an
  imported source outside the scan tree — including one reached through an
  in-tree symlink — cannot adopt an unrelated external project configuration.
  Remapping targets and the
  `lib/`/`node_modules`/root fallbacks are all joined against that sub-project
  root.
- Per-sub-project remappings are loaded once and memoized (`subCache`). The scan
  root reuses the live `Remappings` slice so `AddRemapping` and the eager root
  load keep working.
- `context:prefix=target` remappings from both configuration formats apply only
  when the importing file's path relative to its owning sub-project starts
  with `context`. Applicable mappings are ordered by descending context length,
  then descending import-prefix length, with declaration order preserved for
  exact ties; an empty context is global. Missing or non-regular targets do not
  stop resolution: lookup continues through other mappings and then the
  sub-project's `node_modules`, `lib`, and root locations. Only an existing
  regular file is accepted as a resolved non-relative import.

**Exports:**
- `Resolver` struct - Handles import resolution with remappings
- `NewResolver(projectRoot)` - Creates resolver with auto-loaded remappings
- `Resolve(importPath, fromFile)` - Resolve import to absolute path (sub-project aware)
- `AddRemapping(from, to)` - Add custom remapping

**Key internals:**
- `loadRemappingsFor(root, framework)` - Gather remappings.txt + foundry.toml + defaults for one root
- `remappings.go` - Parse context-aware remapping specs, select the active
  Foundry profile, and deterministically order applicable mappings
- `findSubRoot(fromFile)` / `subProjectFor(fromFile)` - Locate and cache the owning sub-project

**Used by:** Reader's `ResolveImports()` to load dependency files on-demand

### imports.go
Solidity-aware import directive extraction used before path resolution.

- Tokenizes identifiers, quoted strings, and punctuation while skipping
  whitespace plus line/block comments.
- Validates all Solidity import forms before returning a path, including
  multiline directives and aliases.
- Consumes non-import string literals atomically, preventing false
  `import.unresolved` diagnostics from import-shaped string contents.
- Decodes Solidity string escapes (`\\n`, `\\r`, `\\t`, quotes/backslashes,
  `\\xNN`, `\\uNNNN`, and escaped physical line breaks) before resolving the
  path. Malformed escapes, Unicode surrogate code points, and invalid
  ordinary-string bytes invalidate the directive instead of producing a
  different filesystem path.
- Deduplicates paths in first-seen order.

### git.go
Git repository detection and URL building.

**Purpose:** Detect git repositories and convert file paths to web URLs

**Exports:**
- `GitInfo` struct - Contains RemoteURL and Branch
- `DetectGitInfo(projectRoot)` - Detect git remote and branch from .git directory
- `GitRemoteToWebURL(remote)` - Convert SSH/HTTPS git URL to web URL
- `BuildGitFileURL(gitInfo, projectRoot, filePath)` - Build blob URL for file

**Detection:**
- Reads `.git/config` for remote origin URL
- Reads `.git/HEAD` for current branch
- Supports SSH (`git@github.com:...`) and HTTPS formats
- Converts to web URL format (e.g., `https://github.com/user/repo`)

**Used by:** Report package for generating clickable file links

## Usage Flow

```go
log := logging.New(true, output)
r := reader.NewWithOptions(reader.Options{Logger: log})
sources, err := r.Read("./contracts/")
// Resolve imports recursively
err = r.ResolveImports(projectRoot)
sources = r.GetAllSources() // Get all files including dependencies
diagnostics := r.Diagnostics() // pass to builder.Options.Diagnostics
// sources ready for builder
```

## Import Resolution Flow

```
1. Read project files from src/
2. For each file:
   - Lex and validate real Solidity import directives
   - Resolve import path using Resolver (remappings)
   - Load file if not already loaded
   - Recursively process imports from newly loaded file
3. Return all files (project + dependencies)
```

## Integration Points

**Output:** Used by `builder` package as input for database construction

**Data Structure:** Returns `[]*types.SourceFile` where each has:
- `Path` (string) - Absolute file path
- `Content` (string) - Raw Solidity code
- `ResolvedImports` (`[]string`) - Canonical absolute imported files actually
  selected by the resolver; additive/omitted in older caches
- `ImportBindings` (`[]types.ImportBinding`) - Additive per-directive raw path
  plus canonical resolved file; aliases are enriched by the builder
- `PragmaVersion` (string) - Solidity version from pragma directive (**used by engine for version checks**)
- Other fields populated later by builder

## Design Notes

- **Recursive scanning** to find all .sol files
- **Smart exclusions** to avoid build/test directories (dependencies still skipped from scanning)
- **Import resolution** loads dependency files on-demand without scanning entire directories
- **Framework detection** helps understand project structure
- **Tolerant** - continues on errors, returns what it found
- **Version preservation** - Pragma version stored for template version constraints
- **Cycle prevention** - Tracks loaded files to prevent infinite loops
- **Remapping support** - Fully integrated with Foundry/Hardhat remapping systems
