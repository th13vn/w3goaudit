// Package logging provides scan-local verbose logging for w3goaudit.
package logging

import (
	"fmt"
	"io"
	"sync"
)

// Logger is an immutable logging configuration with serialized writes.
// Separate scans should construct separate Logger values so their output
// destinations and enabled state cannot affect each other.
type Logger struct {
	mu      sync.Mutex
	enabled bool
	writer  io.Writer
}

// New constructs a logger. A nil writer is treated as io.Discard.
func New(enabled bool, writer io.Writer) *Logger {
	if writer == nil {
		writer = io.Discard
	}
	return &Logger{enabled: enabled, writer: writer}
}

// Disabled returns a logger that discards all messages.
func Disabled() *Logger {
	return New(false, io.Discard)
}

// Enabled reports whether the logger emits messages.
func (l *Logger) Enabled() bool {
	return l != nil && l.enabled
}

// Printf writes one newline-terminated message when logging is enabled.
// Writes through a Logger are serialized so concurrent analysis stages cannot
// interleave partial messages in the shared scan log.
func (l *Logger) Printf(format string, args ...any) {
	if l == nil || !l.enabled {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = fmt.Fprintf(l.writer, format+"\n", args...)
}
