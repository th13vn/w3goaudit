package types

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/logging"
)

func TestLoadFromJSONScanLocalLoggerIsolation(t *testing.T) {
	writeDB := func(name string) string {
		path := filepath.Join(t.TempDir(), name+".json")
		data, err := json.Marshal(NewDatabaseWithOptions(DatabaseOptions{Logger: logging.Disabled()}))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	leftPath := writeDB("left-db")
	rightPath := writeDB("right-db")

	var left, right bytes.Buffer
	var wg sync.WaitGroup
	for _, tc := range []struct {
		path   string
		logger *logging.Logger
	}{{leftPath, logging.New(true, &left)}, {rightPath, logging.New(true, &right)}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := LoadFromJSONWithOptions(tc.path, LoadOptions{Logger: tc.logger}); err != nil {
				t.Errorf("LoadFromJSONWithOptions(%s): %v", tc.path, err)
			}
		}()
	}
	wg.Wait()

	if strings.Contains(left.String(), rightPath) || strings.Contains(right.String(), leftPath) {
		t.Fatalf("database logs crossed streams: left=%q right=%q", left.String(), right.String())
	}
	if !strings.Contains(left.String(), leftPath) || !strings.Contains(right.String(), rightPath) {
		t.Fatalf("database logs missing paths: left=%q right=%q", left.String(), right.String())
	}
}
