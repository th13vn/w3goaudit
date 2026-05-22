// W3GoAudit - Solidity Smart Contract Audit Engine
//
// A CLI tool for scanning and auditing Solidity smart contracts
// using rule-based templates (WQL).
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
