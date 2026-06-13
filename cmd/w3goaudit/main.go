// W3GoAudit - Solidity Smart Contract Audit Engine
//
// A CLI tool for scanning and auditing Solidity smart contracts
// using rule-based templates (WQL).
package main

import (
	"errors"
	"fmt"
	"os"
)

// exitFindings is the exit code used when --fail-on trips on findings at or
// above the configured severity. It is distinct from runtime errors (exit 1) so
// CI can tell "scan ran, found gated issues" apart from "scan failed to run".
const exitFindings = 2

// failOnError signals that the scan completed successfully but findings met the
// --fail-on threshold. main converts it to exitFindings without printing the
// usage block.
type failOnError struct{ msg string }

func (e *failOnError) Error() string { return e.msg }

func main() {
	if err := rootCmd.Execute(); err != nil {
		var fe *failOnError
		if errors.As(err, &fe) {
			fmt.Fprintln(os.Stderr, fe.Error())
			os.Exit(exitFindings)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
