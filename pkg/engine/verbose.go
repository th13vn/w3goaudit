package engine

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// VerboseEnabled controls whether verbose logging is enabled
var VerboseEnabled = false

// verboseWriter is the output destination for logs (default: stdout)
var (
	legacyMu      sync.Mutex
	verboseWriter io.Writer = os.Stdout
)

// SetVerboseWriter sets a custom writer for verbose output.
//
// Deprecated: construct engines with Options.Logger or load templates with
// TemplateLoadOptions.Logger.
func SetVerboseWriter(w io.Writer) {
	legacyMu.Lock()
	defer legacyMu.Unlock()
	verboseWriter = w
}

// VerboseLog prints a verbose message if enabled.
//
// Deprecated: construct engines with Options.Logger or load templates with
// TemplateLoadOptions.Logger.
func VerboseLog(format string, args ...interface{}) {
	legacyMu.Lock()
	defer legacyMu.Unlock()
	if VerboseEnabled && verboseWriter != nil {
		_, _ = fmt.Fprintf(verboseWriter, format+"\n", args...)
	}
}
