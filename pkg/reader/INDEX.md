# pkg/reader - Source File Reading

## Purpose

Discovers and loads Solidity source files from the filesystem with intelligent project detection.

## Key Files

### reader.go
Main file reader implementation.

**Exports:**
- `Reader` struct - Manages file reading state
- `New()` - Creates new reader instance
- `Read(path)` - Auto-detect file or directory and read
- `ReadFile(path)` - Read single .sol file
- `ReadFiles(paths)` - Read multiple files
- `ReadDirectory(path)` - Recursively read directory

**Auto-excluded directories:**
- `node_modules`, `out`, `artifacts`, `cache`, `test`, `lib`, `mocks`, `broadcast`, etc.

**Returns:** `[]*types.SourceFile` with:
- File path (absolute)
- File content (string)
- Content Checksum (SHA256)
- Contracts list (populated by builder)
- Imports list (populated by builder)
- Pragma version (populated by builder) - **Used for version checking**

**Import Resolution:**
- `ResolveImports(projectRoot)` - Recursively load imported files
- Uses `Resolver` to map import paths via remappings
- Only loads files that are actually imported
- Prevents duplicate loading with `loadedPaths` tracking (keyed by canonical path)
- Handles transitive dependencies automatically

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
Debug logging infrastructure.

**Exports:**
- `VerboseEnabled` - Global flag to enable/disable verbose logging
- `VerboseLog(format, args...)` - Conditional verbose logging function
- `SetVerboseWriter(w io.Writer)` - Set custom output writer for verbose logs (default: os.Stdout)

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
- Handle npm/node_modules imports  
- Support remappings from remappings.txt (Foundry)
- Support dependencies directory (Soldeer)

**Exports:**
- `Resolver` struct - Handles import resolution with remappings
- `NewResolver(projectRoot)` - Creates resolver with auto-loaded remappings
- `Resolve(importPath, fromFile)` - Resolve import to absolute path
- `AddRemapping(from, to)` - Add custom remapping

**Used by:** Reader's `ResolveImports()` to load dependency files on-demand

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
r := reader.New()
sources, err := r.Read("./contracts/")
// Resolve imports recursively
err = r.ResolveImports(projectRoot)
sources = r.GetAllSources() // Get all files including dependencies
// sources ready for builder
```

## Import Resolution Flow

```
1. Read project files from src/
2. For each file:
   - Extract import statements via regex
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
