package logging

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestLoggerIsolation(t *testing.T) {
	var left, right bytes.Buffer
	l := New(true, &left)
	r := New(true, &right)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			l.Printf("left")
		}()
		go func() {
			defer wg.Done()
			r.Printf("right")
		}()
	}
	wg.Wait()

	if strings.Contains(left.String(), "right") || strings.Contains(right.String(), "left") {
		t.Fatalf("scan-local loggers crossed streams: left=%q right=%q", left.String(), right.String())
	}
	if got := strings.Count(left.String(), "left\n"); got != 50 {
		t.Fatalf("left messages = %d, want 50", got)
	}
	if got := strings.Count(right.String(), "right\n"); got != 50 {
		t.Fatalf("right messages = %d, want 50", got)
	}
}

func TestLoggerDisabledAndNilWriter(t *testing.T) {
	var out bytes.Buffer
	Disabled().Printf("hidden")
	New(false, &out).Printf("hidden")
	New(true, nil).Printf("discarded")
	if out.Len() != 0 {
		t.Fatalf("disabled logger wrote %q", out.String())
	}
}
