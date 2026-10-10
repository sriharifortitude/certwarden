// Command certwarden audits X.509 certificates and certificate chains offline.
package main

import (
	"os"
	"time"

	"github.com/sriharifortitude/certwarden/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr, time.Now))
}
