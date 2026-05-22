package types

import (
	"fmt"
	"io"
	"os"
)

// VerboseEnabled controls whether verbose logging is enabled
var VerboseEnabled = false

// verboseWriter is the output destination for logs (default: stdout)
var verboseWriter io.Writer = os.Stdout

// SetVerboseWriter sets a custom writer for verbose output
func SetVerboseWriter(w io.Writer) {
	verboseWriter = w
}

// VerboseLog prints a verbose message if enabled
func VerboseLog(format string, args ...interface{}) {
	if VerboseEnabled && verboseWriter != nil {
		fmt.Fprintf(verboseWriter, format+"\n", args...)
	}
}
