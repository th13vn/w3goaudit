package reader

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// TestReadDirectoryBuildDatabaseFixtures verifies ReadDirectory discovers the
// expected .sol fixtures under test-data/core/build-database and that GetAllSources
// returns their contents.
func TestReadDirectoryBuildDatabaseFixtures(t *testing.T) {
	const fixtureDir = "../../test-data/core/build-database"
	if _, err := os.Stat(fixtureDir); err != nil {
		t.Skipf("fixture directory not available: %v", err)
	}

	// Count the .sol files actually on disk so the test stays correct if
	// fixtures are added/removed.
	var wantNames []string
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatalf("reading fixture dir: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sol") {
			wantNames = append(wantNames, e.Name())
		}
	}
	if len(wantNames) == 0 {
		t.Fatal("expected at least one .sol fixture, found none")
	}

	r := New()
	got, err := r.ReadDirectory(fixtureDir)
	if err != nil {
		t.Fatalf("ReadDirectory: %v", err)
	}

	if len(got) != len(wantNames) {
		t.Errorf("ReadDirectory returned %d files, want %d", len(got), len(wantNames))
	}

	// Every returned file must be a .sol with non-empty content.
	for _, sf := range got {
		if !strings.HasSuffix(sf.Path, ".sol") {
			t.Errorf("non-.sol file returned: %s", sf.Path)
		}
		if sf.Content == "" {
			t.Errorf("empty content for %s", sf.Path)
		}
		if sf.Checksum == "" {
			t.Errorf("missing checksum for %s", sf.Path)
		}
	}

	// GetAllSources must match what ReadDirectory returned.
	all := r.GetAllSources()
	if len(all) != len(got) {
		t.Errorf("GetAllSources returned %d, ReadDirectory returned %d", len(all), len(got))
	}

	// Confirm the expected base names are present.
	gotNames := make(map[string]bool)
	for _, sf := range got {
		gotNames[filepath.Base(sf.Path)] = true
	}
	for _, name := range wantNames {
		if !gotNames[name] {
			t.Errorf("expected fixture %q not discovered", name)
		}
	}
}

// TestReadDirectorySkipsExcludedDirs verifies node_modules (and other excluded
// directories) are skipped while a top-level .sol file is still discovered.
func TestReadDirectorySkipsExcludedDirs(t *testing.T) {
	root := t.TempDir()

	mustWrite(t, filepath.Join(root, "Main.sol"), "contract Main {}\n")

	// node_modules is in the excluded-dir list in reader.go.
	nm := filepath.Join(root, "node_modules")
	if err := os.MkdirAll(nm, 0o755); err != nil {
		t.Fatalf("mkdir node_modules: %v", err)
	}
	mustWrite(t, filepath.Join(nm, "Dep.sol"), "contract Dep {}\n")

	// A hidden directory should also be skipped.
	hidden := filepath.Join(root, ".hidden")
	if err := os.MkdirAll(hidden, 0o755); err != nil {
		t.Fatalf("mkdir .hidden: %v", err)
	}
	mustWrite(t, filepath.Join(hidden, "Hidden.sol"), "contract Hidden {}\n")

	r := New()
	got, err := r.ReadDirectory(root)
	if err != nil {
		t.Fatalf("ReadDirectory: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 file (Main.sol), got %d", len(got))
	}
	if base := filepath.Base(got[0].Path); base != "Main.sol" {
		t.Errorf("expected Main.sol, got %s", base)
	}
}

// TestReadFileStripsBOM verifies a leading UTF-8 BOM is removed from content.
func TestReadFileStripsBOM(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Bom.sol")

	const bom = "\xEF\xBB\xBF"
	const body = "pragma solidity ^0.8.0;\ncontract Bom {}\n"
	mustWrite(t, path, bom+body)

	r := New()
	sf, err := r.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if strings.HasPrefix(sf.Content, bom) {
		t.Error("content still has BOM prefix after ReadFile")
	}
	if sf.Content != body {
		t.Errorf("content mismatch after BOM strip:\n got: %q\nwant: %q", sf.Content, body)
	}
}

// TestReadFileRejectsNonSol verifies ReadFile errors on non-.sol files.
func TestReadFileRejectsNonSol(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "notes.txt")
	mustWrite(t, path, "not solidity")

	r := New()
	if _, err := r.ReadFile(path); err == nil {
		t.Error("expected error for non-.sol file, got nil")
	}
}

// TestReadFileDeduplicates verifies reading the same file twice returns the same
// entry without duplicating SourceFiles.
func TestReadFileDeduplicates(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Dup.sol")
	mustWrite(t, path, "contract Dup {}\n")

	r := New()
	if _, err := r.ReadFile(path); err != nil {
		t.Fatalf("first ReadFile: %v", err)
	}
	if _, err := r.ReadFile(path); err != nil {
		t.Fatalf("second ReadFile: %v", err)
	}

	if n := len(r.GetAllSources()); n != 1 {
		t.Errorf("expected 1 source after duplicate read, got %d", n)
	}
}

func TestResolveImportsRecordsDurableDiagnostic(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Main.sol")
	mustWrite(t, path, `pragma solidity ^0.8.20;
import "./Missing.sol";
import "./Missing.sol";
contract Main is Missing {}
`)

	r := New()
	sources, err := r.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	canonicalPath := sources[0].Path
	if err := r.ResolveImports(root); err != nil {
		t.Fatalf("ResolveImports: %v", err)
	}

	diagnostics := r.Diagnostics()
	if len(diagnostics) != 1 {
		t.Fatalf("Diagnostics() = %#v, want one deduplicated unresolved import", diagnostics)
	}
	d := diagnostics[0]
	if d.Code != types.DiagnosticUnresolvedImport || d.Severity != types.DiagnosticWarning || d.Phase != "reader" {
		t.Fatalf("diagnostic identity = %#v", d)
	}
	if d.File != canonicalPath || d.ImportPath != "./Missing.sol" || !d.Incomplete || d.Message == "" {
		t.Fatalf("diagnostic detail = %#v", d)
	}

	// Preserve the legacy compatibility view over the same durable records.
	unresolved := r.UnresolvedImports()
	if len(unresolved) != 1 || unresolved[0].FromFile != canonicalPath || unresolved[0].ImportPath != "./Missing.sol" {
		t.Fatalf("UnresolvedImports() = %#v", unresolved)
	}

	// Both accessors return defensive values.
	diagnostics[0].Message = "mutated"
	if got := r.Diagnostics()[0].Message; got == "mutated" {
		t.Fatal("Diagnostics returned mutable reader-owned state")
	}
}

// TestDetectFramework verifies framework detection for each marker file.
func TestDetectFramework(t *testing.T) {
	tests := []struct {
		name    string
		markers map[string]string // filename -> content
		wantFW  Framework
	}{
		{
			name:    "foundry",
			markers: map[string]string{"foundry.toml": "[profile.default]\n"},
			wantFW:  FrameworkFoundry,
		},
		{
			name:    "hardhat js",
			markers: map[string]string{"hardhat.config.js": "module.exports = {};\n"},
			wantFW:  FrameworkHardhat,
		},
		{
			name:    "hardhat ts",
			markers: map[string]string{"hardhat.config.ts": "export default {};\n"},
			wantFW:  FrameworkHardhat,
		},
		{
			name:    "truffle",
			markers: map[string]string{"truffle-config.js": "module.exports = {};\n"},
			wantFW:  FrameworkTruffle,
		},
		{
			name:    "brownie",
			markers: map[string]string{"brownie-config.yaml": "project_structure:\n"},
			wantFW:  FrameworkBrownie,
		},
		{
			name:    "unknown",
			markers: map[string]string{"README.md": "# nothing\n"},
			wantFW:  FrameworkUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for fn, content := range tt.markers {
				mustWrite(t, filepath.Join(root, fn), content)
			}
			if got := DetectFramework(root); got != tt.wantFW {
				t.Errorf("DetectFramework = %q, want %q", got, tt.wantFW)
			}
		})
	}
}

// TestDetectProjectRoot verifies the root is detected by walking up to a marker.
func TestDetectProjectRoot(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "foundry.toml"), "[profile.default]\n")

	sub := filepath.Join(root, "src", "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	srcFile := filepath.Join(sub, "A.sol")
	mustWrite(t, srcFile, "contract A {}\n")

	got, err := DetectProjectRoot(srcFile)
	if err != nil {
		t.Fatalf("DetectProjectRoot: %v", err)
	}

	wantRoot, _ := filepath.EvalSymlinks(root)
	gotRoot, _ := filepath.EvalSymlinks(got)
	if gotRoot != wantRoot {
		t.Errorf("DetectProjectRoot = %q, want %q", gotRoot, wantRoot)
	}
}

// TestResolverRelativeImport verifies relative import resolution to an absolute
// path that points at the actual file.
func TestResolverRelativeImport(t *testing.T) {
	root := t.TempDir()

	srcDir := filepath.Join(root, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	fromFile := filepath.Join(srcDir, "A.sol")
	target := filepath.Join(srcDir, "B.sol")
	mustWrite(t, fromFile, `import "./B.sol";`+"\n")
	mustWrite(t, target, "contract B {}\n")

	res := NewResolver(root)
	resolved, err := res.Resolve("./B.sol", fromFile)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if !filepath.IsAbs(resolved) {
		t.Errorf("resolved path not absolute: %s", resolved)
	}
	// Compare via EvalSymlinks since macOS temp dirs are symlinked.
	gotReal, _ := filepath.EvalSymlinks(resolved)
	wantReal, _ := filepath.EvalSymlinks(target)
	if gotReal != wantReal {
		t.Errorf("resolved = %q, want %q", gotReal, wantReal)
	}
}

// TestResolverRemapping verifies remapping resolution via AddRemapping
// (@openzeppelin-style prefix) within a temp project.
func TestResolverRemapping(t *testing.T) {
	root := t.TempDir()

	// Create the target file the remapping points to.
	ozDir := filepath.Join(root, "node_modules", "@openzeppelin", "contracts", "token")
	if err := os.MkdirAll(ozDir, 0o755); err != nil {
		t.Fatalf("mkdir oz: %v", err)
	}
	target := filepath.Join(ozDir, "ERC20.sol")
	mustWrite(t, target, "contract ERC20 {}\n")

	res := NewResolver(root)
	res.AddRemapping("@openzeppelin/contracts/", filepath.Join(root, "node_modules", "@openzeppelin", "contracts")+"/")

	fromFile := filepath.Join(root, "src", "A.sol")
	resolved, err := res.Resolve("@openzeppelin/contracts/token/ERC20.sol", fromFile)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	gotReal, _ := filepath.EvalSymlinks(resolved)
	wantReal, _ := filepath.EvalSymlinks(target)
	if gotReal != wantReal {
		t.Errorf("remapped resolved = %q, want %q", gotReal, wantReal)
	}
}

// TestResolverRemappingsTxt verifies remappings.txt is auto-loaded by NewResolver.
func TestResolverRemappingsTxt(t *testing.T) {
	root := t.TempDir()

	libDir := filepath.Join(root, "vendor", "solmate")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatalf("mkdir vendor: %v", err)
	}
	target := filepath.Join(libDir, "Auth.sol")
	mustWrite(t, target, "contract Auth {}\n")

	// remappings.txt: solmate/ => vendor/solmate/ (relative to project root)
	mustWrite(t, filepath.Join(root, "remappings.txt"), "solmate/=vendor/solmate/\n")

	res := NewResolver(root)
	found := false
	for _, rm := range res.Remappings {
		if rm.From == "solmate/" {
			found = true
		}
	}
	if !found {
		t.Fatalf("remappings.txt entry not loaded; got %+v", res.Remappings)
	}

	fromFile := filepath.Join(root, "src", "A.sol")
	resolved, err := res.Resolve("solmate/Auth.sol", fromFile)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	gotReal, _ := filepath.EvalSymlinks(resolved)
	wantReal, _ := filepath.EvalSymlinks(target)
	if gotReal != wantReal {
		t.Errorf("remappings.txt resolved = %q, want %q", gotReal, wantReal)
	}
}

// TestResolverFoundryTomlRemappings verifies that remappings declared inside
// foundry.toml (the `remappings = [...]` array, used when auto_detect_remappings
// is off and there is no remappings.txt) are parsed and used by Resolve.
func TestResolverFoundryTomlRemappings(t *testing.T) {
	root := t.TempDir()

	ozDir := filepath.Join(root, "lib", "openzeppelin-contracts", "contracts", "access")
	if err := os.MkdirAll(ozDir, 0o755); err != nil {
		t.Fatalf("mkdir oz: %v", err)
	}
	target := filepath.Join(ozDir, "AccessControl.sol")
	mustWrite(t, target, "contract AccessControl {}\n")

	mustWrite(t, filepath.Join(root, "foundry.toml"),
		"[profile.default]\n"+
			"src = \"src\"\n"+
			"auto_detect_remappings = false\n"+
			"remappings = [\n"+
			"  \"@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/\",\n"+
			"]\n")

	res := NewResolver(root)
	fromFile := filepath.Join(root, "src", "A.sol")
	resolved, err := res.Resolve("@openzeppelin/contracts/access/AccessControl.sol", fromFile)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	gotReal, _ := filepath.EvalSymlinks(resolved)
	wantReal, _ := filepath.EvalSymlinks(target)
	if gotReal != wantReal {
		t.Errorf("foundry.toml remap resolved = %q, want %q", gotReal, wantReal)
	}
}

// TestResolverMonorepoSubProject verifies that in a monorepo where the scan root
// (e.g. a git root) has no foundry.toml, imports are resolved against each file's
// nearest enclosing sub-project — which carries its own foundry.toml remappings
// and its own lib/. This mirrors the kuladao-kula-eip-suite layout.
func TestResolverMonorepoSubProject(t *testing.T) {
	root := t.TempDir() // git root — deliberately has NO foundry.toml/remappings.

	pkg := filepath.Join(root, "packages", "eip-3-transfer-domain")
	ozDir := filepath.Join(pkg, "lib", "openzeppelin-contracts", "contracts", "access")
	if err := os.MkdirAll(ozDir, 0o755); err != nil {
		t.Fatalf("mkdir oz: %v", err)
	}
	target := filepath.Join(ozDir, "AccessControl.sol")
	mustWrite(t, target, "contract AccessControl {}\n")

	mustWrite(t, filepath.Join(pkg, "foundry.toml"),
		"[profile.default]\n"+
			"auto_detect_remappings = false\n"+
			"remappings = [\"@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/\"]\n")

	srcDir := filepath.Join(pkg, "src", "reference")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	fromFile := filepath.Join(srcDir, "TransferDomainRegistry.sol")
	mustWrite(t, fromFile, "import {AccessControl} from \"@openzeppelin/contracts/access/AccessControl.sol\";\n")

	// Resolver is rooted at the git root, exactly as the CLI builds it.
	res := NewResolver(root)
	resolved, err := res.Resolve("@openzeppelin/contracts/access/AccessControl.sol", fromFile)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	gotReal, _ := filepath.EvalSymlinks(resolved)
	wantReal, _ := filepath.EvalSymlinks(target)
	if gotReal != wantReal {
		t.Errorf("monorepo sub-project resolved = %q, want %q", gotReal, wantReal)
	}
}

func TestResolverUsesMostSpecificExistingRemapping(t *testing.T) {
	root := t.TempDir()
	want := filepath.Join(root, "vendor", "oz", "Token.sol")
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatalf("mkdir remapping target: %v", err)
	}
	mustWrite(t, want, "contract Token {}\n")

	res := NewResolver(root)
	res.Remappings = []Remapping{
		{From: "@oz/", To: "missing/"},
		{From: "@oz/contracts/", To: "vendor/oz/"},
	}

	got, err := res.Resolve("@oz/contracts/Token.sol", filepath.Join(root, "src", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("Resolve = %q, want most-specific existing remapping %q", got, want)
	}
}

func TestResolverFallsThroughMissingSpecificRemapping(t *testing.T) {
	root := t.TempDir()
	want := filepath.Join(root, "vendor", "contracts", "Token.sol")
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatalf("mkdir remapping target: %v", err)
	}
	mustWrite(t, want, "contract Token {}\n")

	res := NewResolver(root)
	res.Remappings = []Remapping{
		{From: "@oz/", To: "vendor/"},
		{From: "@oz/contracts/", To: "missing/"},
	}

	got, err := res.Resolve("@oz/contracts/Token.sol", filepath.Join(root, "src", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("Resolve = %q, want less-specific existing remapping %q", got, want)
	}
}

func TestResolverFallsThroughMissingRemappingToStandardLocations(t *testing.T) {
	for _, dir := range []string{"node_modules", "lib", ""} {
		name := dir
		if name == "" {
			name = "root"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			want := filepath.Join(root, dir, "pkg", "Token.sol")
			if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
				t.Fatalf("mkdir fallback target: %v", err)
			}
			mustWrite(t, want, "contract Token {}\n")

			res := NewResolver(root)
			res.Remappings = []Remapping{{From: "pkg/", To: "missing/"}}

			got, err := res.Resolve("pkg/Token.sol", filepath.Join(root, "src", "A.sol"))
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if filepath.Clean(got) != filepath.Clean(want) {
				t.Fatalf("Resolve = %q, want fallback %q", got, want)
			}
		})
	}
}

func TestResolverPreservesDeclarationOrderForEqualPrefixes(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first", "Token.sol")
	second := filepath.Join(root, "second", "Token.sol")
	if err := os.MkdirAll(filepath.Dir(first), 0o755); err != nil {
		t.Fatalf("mkdir first remapping target: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(second), 0o755); err != nil {
		t.Fatalf("mkdir second remapping target: %v", err)
	}
	mustWrite(t, first, "contract First {}\n")
	mustWrite(t, second, "contract Second {}\n")

	res := NewResolver(root)
	res.Remappings = []Remapping{
		{From: "pkg/", To: "first/"},
		{From: "pkg/", To: "second/"},
	}

	got, err := res.Resolve("pkg/Token.sol", filepath.Join(root, "src", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(first) {
		t.Fatalf("Resolve = %q, want first equal-prefix remapping %q", got, first)
	}
}

func TestResolverFallsThroughNonRegularCandidates(t *testing.T) {
	root := t.TempDir()
	remappedDir := filepath.Join(root, "mapped", "Token.sol")
	nodeModulesDir := filepath.Join(root, "node_modules", "pkg", "Token.sol")
	if err := os.MkdirAll(remappedDir, 0o755); err != nil {
		t.Fatalf("mkdir remapping candidate: %v", err)
	}
	if err := os.MkdirAll(nodeModulesDir, 0o755); err != nil {
		t.Fatalf("mkdir node_modules candidate: %v", err)
	}
	want := filepath.Join(root, "lib", "pkg", "Token.sol")
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatalf("mkdir lib target: %v", err)
	}
	mustWrite(t, want, "contract Token {}\n")

	res := NewResolver(root)
	res.Remappings = []Remapping{{From: "pkg/", To: "mapped/"}}

	got, err := res.Resolve("pkg/Token.sol", filepath.Join(root, "src", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("Resolve = %q, want first regular-file candidate %q", got, want)
	}
}

func TestResolverRejectsNonRegularLibAndRootCandidates(t *testing.T) {
	t.Run("lib falls through to root", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "lib", "pkg", "Token.sol"), 0o755); err != nil {
			t.Fatalf("mkdir lib candidate: %v", err)
		}
		want := filepath.Join(root, "pkg", "Token.sol")
		if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
			t.Fatalf("mkdir root target: %v", err)
		}
		mustWrite(t, want, "contract Token {}\n")

		got, err := NewResolver(root).Resolve("pkg/Token.sol", filepath.Join(root, "src", "A.sol"))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if filepath.Clean(got) != filepath.Clean(want) {
			t.Fatalf("Resolve = %q, want root regular file %q", got, want)
		}
	})

	t.Run("root remains unresolved", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "pkg", "Token.sol"), 0o755); err != nil {
			t.Fatalf("mkdir root candidate: %v", err)
		}

		const importPath = "pkg/Token.sol"
		got, err := NewResolver(root).Resolve(importPath, filepath.Join(root, "src", "A.sol"))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got != importPath {
			t.Fatalf("Resolve = %q, want unresolved import %q", got, importPath)
		}
	})
}

// TestGitRemoteToWebURL verifies SSH/HTTPS remote normalization (pure function,
// no external dependency).
func TestGitRemoteToWebURL(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"git@github.com:user/repo.git", "https://github.com/user/repo"},
		{"https://github.com/user/repo.git", "https://github.com/user/repo"},
		{"https://github.com/user/repo", "https://github.com/user/repo"},
		{"ftp://example.com/repo", ""},
	}
	for _, tt := range tests {
		if got := GitRemoteToWebURL(tt.in); got != tt.want {
			t.Errorf("GitRemoteToWebURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestDetectGitInfo creates a real git repo in a temp dir, adds an origin
// remote, and asserts detection. Skips gracefully if git is unavailable.
func TestDetectGitInfo(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}

	root := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command(gitBin, args...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v failed: %v (%s)", args, err, out)
		}
	}

	runGit("init")
	runGit("remote", "add", "origin", "git@github.com:acme/widget.git")

	info := DetectGitInfo(root)
	if info == nil {
		t.Fatal("DetectGitInfo returned nil for a repo with an origin remote")
	}
	if info.RemoteURL != "https://github.com/acme/widget" {
		t.Errorf("RemoteURL = %q, want https://github.com/acme/widget", info.RemoteURL)
	}
	if info.Branch == "" {
		t.Error("Branch should not be empty")
	}
}

// TestDetectGitInfoNoRepo verifies nil is returned when there is no .git dir.
func TestDetectGitInfoNoRepo(t *testing.T) {
	root := t.TempDir()
	if info := DetectGitInfo(root); info != nil {
		t.Errorf("expected nil for non-git dir, got %+v", info)
	}
}

// mustWrite writes a file, failing the test on error.
func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
