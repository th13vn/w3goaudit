package report

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/th13vn/w3goaudit/pkg/logging"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestGeneratorScanLocalLoggerAndClock(t *testing.T) {
	leftTime := time.Unix(10, 0).UTC()
	rightTime := time.Unix(20, 0).UTC()
	newGenerator := func(root string, now time.Time, out *bytes.Buffer) *Generator {
		db := types.NewDatabaseWithOptions(types.DatabaseOptions{Logger: logging.Disabled()})
		db.ProjectRoot = root
		return NewGeneratorWithOptions(db, GeneratorOptions{
			Logger: logging.New(true, out),
			Now:    func() time.Time { return now },
		})
	}

	var left, right bytes.Buffer
	leftGenerator := newGenerator("/tmp/left-project", leftTime, &left)
	rightGenerator := newGenerator("/tmp/right-project", rightTime, &right)
	var leftSummary, rightSummary *SummaryReport
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); leftSummary = leftGenerator.GenerateSummary() }()
	go func() { defer wg.Done(); rightSummary = rightGenerator.GenerateSummary() }()
	wg.Wait()

	if strings.Contains(left.String(), "right-project") || strings.Contains(right.String(), "left-project") {
		t.Fatalf("report logs crossed streams: left=%q right=%q", left.String(), right.String())
	}
	if !leftSummary.GeneratedAt.Equal(leftTime) || !rightSummary.GeneratedAt.Equal(rightTime) {
		t.Fatalf("configured clocks ignored: left=%v right=%v", leftSummary.GeneratedAt, rightSummary.GeneratedAt)
	}
}
