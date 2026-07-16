package builder

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/logging"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestBuilderScanLocalLoggerIsolation(t *testing.T) {
	var left, right bytes.Buffer
	leftBuilder := NewWithOptions(Options{Logger: logging.New(true, &left)})
	rightBuilder := NewWithOptions(Options{Logger: logging.New(true, &right)})

	var wg sync.WaitGroup
	for _, tc := range []struct {
		builder *Builder
		source  *types.SourceFile
	}{
		{leftBuilder, &types.SourceFile{Path: "/tmp/Left.sol", Content: "contract Left { function leftOnly() external {} }"}},
		{rightBuilder, &types.SourceFile{Path: "/tmp/Right.sol", Content: "contract Right { function rightOnly() external {} }"}},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := tc.builder.Build([]*types.SourceFile{tc.source}); err != nil {
				t.Errorf("Build(%s): %v", tc.source.Path, err)
			}
		}()
	}
	wg.Wait()

	if strings.Contains(left.String(), "Right.sol") || strings.Contains(right.String(), "Left.sol") {
		t.Fatalf("builder logs crossed streams: left=%q right=%q", left.String(), right.String())
	}
	if !strings.Contains(left.String(), "Left.sol") || !strings.Contains(right.String(), "Right.sol") {
		t.Fatalf("builder logs missing source paths: left=%q right=%q", left.String(), right.String())
	}
}
