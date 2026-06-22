package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// modulePath is the Go module path used to self-update via `go install`.
const modulePath = "github.com/th13vn/w3goaudit"

// installTarget is the package installed by --update.
const installTarget = modulePath + "/cmd/w3goaudit@latest"

// runSelfUpdate upgrades the tool with the Go toolchain:
//
//	go install github.com/th13vn/w3goaudit/cmd/w3goaudit@latest
//
// This avoids shipping platform-specific binaries — the user's own Go
// installation builds the latest tagged version. A missing `go` toolchain is
// reported clearly rather than failing opaquely.
func runSelfUpdate() error {
	goBin, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("the Go toolchain is required for --update but `go` was not found in PATH\n" +
			"install Go (https://go.dev/dl/) or update manually:\n  go install " + installTarget)
	}

	fmt.Printf("Updating w3goaudit (current %s) via:\n  %s install %s\n\n", Version, goBin, installTarget)

	cmd := exec.Command(goBin, "install", installTarget)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Force module mode in case the user runs this from inside a GOPATH tree.
	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go install failed: %w", err)
	}

	fmt.Printf("\n✓ Updated. The new binary is in %s\n", installBinDir())
	fmt.Println("  Ensure that directory is on your PATH, then run `w3goaudit version`.")
	return nil
}

// installBinDir reports where `go install` places binaries (GOBIN, else
// GOPATH/bin, else ~/go/bin) for a helpful post-update hint.
func installBinDir() string {
	if gobin := os.Getenv("GOBIN"); gobin != "" {
		return gobin
	}
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		// GOPATH may contain multiple entries; the first wins for `go install`.
		first := gopath
		if i := strings.IndexByte(gopath, os.PathListSeparator); i >= 0 {
			first = gopath[:i]
		}
		return filepath.Join(first, "bin")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "go", "bin")
	}
	return "$GOPATH/bin"
}
