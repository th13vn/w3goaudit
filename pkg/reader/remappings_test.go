package reader

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseRemappingsFilePreservesContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "remappings.txt")
	mustWrite(t, path, "src/:pkg/=vendor/pkg/\npkg2/=vendor/pkg2/\n")

	got, err := parseRemappingsFile(path)
	if err != nil {
		t.Fatalf("parseRemappingsFile: %v", err)
	}
	want := []Remapping{
		{Context: "src/", From: "pkg/", To: "vendor/pkg/"},
		{From: "pkg2/", To: "vendor/pkg2/"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseRemappingsFile() = %#v, want %#v", got, want)
	}
}

func TestParseFoundryTomlRemappingsUsesActiveProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foundry.toml")
	mustWrite(t, path, `
# remappings = ["commented/=commented/"]
remappings = ["root/=root/"]

[profile.default]
remappings = [
  "src/:pkg/=default/", # an inline comment must not become data
]

[profile.ci]
remappings = ["test/:pkg/=ci/"]

[profile.inactive]
remappings = ["inactive/=inactive/"]
`)

	t.Run("default", func(t *testing.T) {
		t.Setenv("FOUNDRY_PROFILE", "")
		got, err := parseFoundryTomlRemappings(path)
		if err != nil {
			t.Fatalf("parseFoundryTomlRemappings: %v", err)
		}
		want := []Remapping{{Context: "src/", From: "pkg/", To: "default/"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("default remappings = %#v, want %#v", got, want)
		}
	})

	t.Run("selected", func(t *testing.T) {
		t.Setenv("FOUNDRY_PROFILE", "ci")
		got, err := parseFoundryTomlRemappings(path)
		if err != nil {
			t.Fatalf("parseFoundryTomlRemappings: %v", err)
		}
		want := []Remapping{{Context: "test/", From: "pkg/", To: "ci/"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("ci remappings = %#v, want %#v", got, want)
		}
	})
}

func TestParseFoundryTomlRemappingsInheritsDefaultField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foundry.toml")
	mustWrite(t, path, `
[profile.default]
remappings = ["pkg/=default/"]

[profile.ci]
optimizer = true
`)
	t.Setenv("FOUNDRY_PROFILE", "ci")

	got, err := parseFoundryTomlRemappings(path)
	if err != nil {
		t.Fatalf("parseFoundryTomlRemappings: %v", err)
	}
	want := []Remapping{{From: "pkg/", To: "default/"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inherited remappings = %#v, want %#v", got, want)
	}
}

func TestParseFoundryTomlRemappingsHonorsExplicitEmptyProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foundry.toml")
	mustWrite(t, path, `
[profile.default]
remappings = ["pkg/=default/"]

[profile.ci]
remappings = []
`)
	t.Setenv("FOUNDRY_PROFILE", "ci")

	got, err := parseFoundryTomlRemappings(path)
	if err != nil {
		t.Fatalf("parseFoundryTomlRemappings: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("explicit empty profile remappings = %#v, want none", got)
	}
}

func TestParseFoundryTomlRemappingsRejectsInvalidToml(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foundry.toml")
	mustWrite(t, path, "[profile.default\nremappings = [\"pkg/=vendor/\"]\n")
	if _, err := parseFoundryTomlRemappings(path); err == nil {
		t.Fatal("parseFoundryTomlRemappings accepted invalid TOML")
	}
}

func TestResolverContextOverridesMoreSpecificGlobalPrefix(t *testing.T) {
	root := t.TempDir()
	contextual := filepath.Join(root, "contextual", "contracts", "Token.sol")
	global := filepath.Join(root, "global", "Token.sol")
	writeResolverTarget(t, contextual)
	writeResolverTarget(t, global)

	res := NewResolver(root)
	res.Remappings = []Remapping{
		{From: "pkg/contracts/", To: "global/"},
		{Context: "src/", From: "pkg/", To: "contextual/"},
	}

	got, err := res.Resolve("pkg/contracts/Token.sol", filepath.Join(root, "src", "feature", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve contextual import: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(contextual) {
		t.Fatalf("contextual Resolve = %q, want %q", got, contextual)
	}

	got, err = res.Resolve("pkg/contracts/Token.sol", filepath.Join(root, "test", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve global import: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(global) {
		t.Fatalf("out-of-context Resolve = %q, want global %q", got, global)
	}
}

func TestResolverRanksLongerApplicableContextFirst(t *testing.T) {
	root := t.TempDir()
	broad := filepath.Join(root, "broad", "Token.sol")
	specific := filepath.Join(root, "specific", "contracts", "Token.sol")
	writeResolverTarget(t, broad)
	writeResolverTarget(t, specific)

	res := NewResolver(root)
	res.Remappings = []Remapping{
		{Context: "src/", From: "pkg/contracts/", To: "broad/"},
		{Context: "src/features/", From: "pkg/", To: "specific/"},
	}

	got, err := res.Resolve("pkg/contracts/Token.sol", filepath.Join(root, "src", "features", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(specific) {
		t.Fatalf("Resolve = %q, want longer-context mapping %q", got, specific)
	}
}

func TestResolverContextIsRelativeToOwningSubproject(t *testing.T) {
	t.Setenv("FOUNDRY_PROFILE", "")
	root := t.TempDir()
	subroot := filepath.Join(root, "packages", "app")
	if err := os.MkdirAll(subroot, 0o755); err != nil {
		t.Fatalf("mkdir subproject: %v", err)
	}
	mustWrite(t, filepath.Join(subroot, "foundry.toml"), `
[profile.default]
remappings = ["src/:pkg/=vendor/"]
`)
	want := filepath.Join(subroot, "vendor", "Token.sol")
	writeResolverTarget(t, want)

	got, err := NewResolver(root).Resolve("pkg/Token.sol", filepath.Join(subroot, "src", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("Resolve = %q, want subproject-context target %q", got, want)
	}
}

func TestResolverUsesActiveFoundryProfile(t *testing.T) {
	t.Setenv("FOUNDRY_PROFILE", "ci")
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "foundry.toml"), `
[profile.default]
remappings = ["pkg/=default/"]

[profile.ci]
remappings = ["pkg/=ci/"]
`)
	writeResolverTarget(t, filepath.Join(root, "default", "Token.sol"))
	want := filepath.Join(root, "ci", "Token.sol")
	writeResolverTarget(t, want)

	got, err := NewResolver(root).Resolve("pkg/Token.sol", filepath.Join(root, "src", "A.sol"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("Resolve = %q, want active-profile target %q", got, want)
	}
}

func TestResolverDoesNotAdoptProjectConfigOutsideScanRoot(t *testing.T) {
	t.Setenv("FOUNDRY_PROFILE", "")
	workspace := t.TempDir()
	scanRoot := filepath.Join(workspace, "scan")
	externalRoot := filepath.Join(workspace, "external")
	if err := os.MkdirAll(scanRoot, 0o755); err != nil {
		t.Fatalf("mkdir scan root: %v", err)
	}
	if err := os.MkdirAll(externalRoot, 0o755); err != nil {
		t.Fatalf("mkdir external root: %v", err)
	}
	mustWrite(t, filepath.Join(externalRoot, "foundry.toml"), `
[profile.default]
remappings = ["pkg/=vendor/"]
`)
	externalTarget := filepath.Join(externalRoot, "vendor", "Token.sol")
	writeResolverTarget(t, externalTarget)

	const importPath = "pkg/Token.sol"
	fromFile := filepath.Join(externalRoot, "src", "External.sol")
	got, err := NewResolver(scanRoot).Resolve(importPath, fromFile)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != importPath {
		t.Fatalf("Resolve = %q, adopted config outside scan root and reached %q", got, externalTarget)
	}
}

func TestResolverDoesNotAdoptProjectConfigThroughExternalSymlink(t *testing.T) {
	t.Setenv("FOUNDRY_PROFILE", "")
	workspace := t.TempDir()
	scanRoot := filepath.Join(workspace, "scan")
	externalRoot := filepath.Join(workspace, "external")
	if err := os.MkdirAll(scanRoot, 0o755); err != nil {
		t.Fatalf("mkdir scan root: %v", err)
	}
	if err := os.MkdirAll(externalRoot, 0o755); err != nil {
		t.Fatalf("mkdir external root: %v", err)
	}
	mustWrite(t, filepath.Join(externalRoot, "foundry.toml"), `
[profile.default]
remappings = ["pkg/=vendor/"]
`)
	externalTarget := filepath.Join(externalRoot, "vendor", "Token.sol")
	writeResolverTarget(t, externalTarget)
	if err := os.MkdirAll(filepath.Join(externalRoot, "src"), 0o755); err != nil {
		t.Fatalf("mkdir external src: %v", err)
	}
	mustWrite(t, filepath.Join(externalRoot, "src", "External.sol"), "contract External {}\n")

	linkedRoot := filepath.Join(scanRoot, "linked-external")
	if err := os.Symlink(externalRoot, linkedRoot); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	const importPath = "pkg/Token.sol"
	fromFile := filepath.Join(linkedRoot, "src", "External.sol")
	got, err := NewResolver(scanRoot).Resolve(importPath, fromFile)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != importPath {
		t.Fatalf("Resolve = %q, followed external symlink and adopted %q", got, externalTarget)
	}
}

func writeResolverTarget(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	mustWrite(t, path, "contract Target {}\n")
}
