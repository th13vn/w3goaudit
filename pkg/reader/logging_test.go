package reader

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/logging"
)

func TestReaderScanLocalLoggerIsolation(t *testing.T) {
	leftPath := filepath.Join(t.TempDir(), "Left.sol")
	rightPath := filepath.Join(t.TempDir(), "Right.sol")
	if err := os.WriteFile(leftPath, []byte("contract Left {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rightPath, []byte("contract Right {}"), 0o600); err != nil {
		t.Fatal(err)
	}

	var left, right bytes.Buffer
	leftReader := NewWithOptions(Options{Logger: logging.New(true, &left)})
	rightReader := NewWithOptions(Options{Logger: logging.New(true, &right)})

	var wg sync.WaitGroup
	for _, tc := range []struct {
		reader *Reader
		path   string
	}{{leftReader, leftPath}, {rightReader, rightPath}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := tc.reader.Read(tc.path); err != nil {
				t.Errorf("Read(%s): %v", tc.path, err)
			}
		}()
	}
	wg.Wait()

	if strings.Contains(left.String(), rightPath) || strings.Contains(right.String(), leftPath) {
		t.Fatalf("reader logs crossed streams: left=%q right=%q", left.String(), right.String())
	}
	if !strings.Contains(left.String(), leftPath) || !strings.Contains(right.String(), rightPath) {
		t.Fatalf("reader logs missing paths: left=%q right=%q", left.String(), right.String())
	}
}

func TestLegacyReaderConstructorStillUsesVerboseGlobals(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Legacy.sol")
	if err := os.WriteFile(path, []byte("contract Legacy {}"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	oldEnabled := VerboseEnabled
	VerboseEnabled = true
	SetVerboseWriter(&out)
	defer func() {
		VerboseEnabled = oldEnabled
		SetVerboseWriter(os.Stdout)
	}()

	if _, err := New().Read(path); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), path) {
		t.Fatalf("legacy constructor did not use verbose globals: %q", out.String())
	}
}
