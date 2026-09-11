// Command secret manages machine-local credential files without exposing their
// contents in command arguments.
package main

import (
	"os"

	"github.com/wawrzdev/secret/internal/secret"
)

func main() {
	os.Exit(secret.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
