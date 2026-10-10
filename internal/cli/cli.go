// Package cli is certwarden's command line.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sriharifortitude/certwarden/internal/certs"
)

// Version is set at build time; "dev" otherwise.
var Version = "0.1.0"

const usage = `certwarden: audit X.509 certificates and the chains in certificate files, offline.

usage: certwarden [flags] PATH...

PATH is a PEM or DER file, or a directory searched recursively for .pem .crt .cer .der
.cert and .ca-bundle files.

flags:
  --json            machine-readable output
  --strict          exit 1 on warnings as well as errors
  --warn-days N     warn about certificates that expire within N days (default 30)
  --now TIME        judge validity at this RFC 3339 time instead of now
  --version

exit status: 0 no errors, 1 at least one error (or a warning with --strict), 2 usage error or unreadable path
`

// Run executes the command and returns the exit status.
func Run(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	fs := flag.NewFlagSet("certwarden", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	asJSON := fs.Bool("json", false, "")
	strict := fs.Bool("strict", false, "")
	warnDays := fs.Int("warn-days", 30, "")
	nowFlag := fs.String("now", "", "")
	version := fs.Bool("version", false, "")
	help := fs.Bool("help", false, "")

	// The flag package stops at the first non-flag; flags are allowed after paths here.
	var paths []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			fmt.Fprintf(stderr, "certwarden: %v\n\n%s", err, usage)
			return 2
		}
		rest = fs.Args()
		if len(rest) > 0 {
			if rest[0] == "--" {
				paths = append(paths, rest[1:]...)
				break
			}
			paths = append(paths, rest[0])
			rest = rest[1:]
		}
	}
	switch {
	case *help:
		fmt.Fprint(stdout, usage)
		return 0
	case *version:
		fmt.Fprintf(stdout, "certwarden %s\n", Version)
		return 0
	case len(paths) == 0:
		fmt.Fprint(stderr, usage)
		return 2
	case *warnDays < 0 || *warnDays > 3650:
		fmt.Fprintln(stderr, "certwarden: --warn-days must be between 0 and 3650")
		return 2
	}

	at := now()
	if *nowFlag != "" {
		t, err := time.Parse(time.RFC3339, *nowFlag)
		if err != nil {
			fmt.Fprintf(stderr, "certwarden: --now must be an RFC 3339 time such as 2026-10-10T00:00:00Z: %v\n", err)
			return 2
		}
		at = t
	}

	files, err := certs.Load(paths)
	if err != nil {
		fmt.Fprintf(stderr, "certwarden: %v\n", err)
		return 2
	}
	reports := certs.Audit(files, certs.Options{Now: at, WarnDays: *warnDays})

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if reports == nil {
			reports = []*certs.Report{}
		}
		if err := enc.Encode(reports); err != nil {
			fmt.Fprintf(stderr, "certwarden: %v\n", err)
			return 2
		}
	} else {
		for i, r := range reports {
			if i > 0 {
				fmt.Fprintln(stdout)
			}
			fmt.Fprint(stdout, Render(r))
		}
		if len(reports) == 0 {
			fmt.Fprintln(stdout, "no certificate files found")
		}
	}

	failed := false
	for _, r := range reports {
		if r.Count(certs.Error) > 0 || (*strict && r.Count(certs.Warning) > 0) {
			failed = true
		}
	}
	if failed {
		return 1
	}
	return 0
}

// Render formats one report as text.
func Render(r *certs.Report) string {
	var b strings.Builder
	errs, warns := r.Count(certs.Error), r.Count(certs.Warning)
	fmt.Fprintf(&b, "%s: %s", r.Path, plural(len(r.Certs), "certificate"))
	switch {
	case errs > 0:
		fmt.Fprintf(&b, ", %s, %s", plural(errs, "error"), plural(warns, "warning"))
	case warns > 0:
		fmt.Fprintf(&b, ", no errors, %s", plural(warns, "warning"))
	case len(r.Findings) == 0 && len(r.Certs) > 0:
		b.WriteString(", no findings")
	}
	b.WriteByte('\n')
	for _, c := range r.Certs {
		left := fmt.Sprintf("%d days left", c.DaysLeft)
		if c.DaysLeft < 0 {
			left = fmt.Sprintf("expired %d days ago", -c.DaysLeft)
		}
		fmt.Fprintf(&b, "  #%d %-4s %s  [%s, %s, %s to %s, %s]\n", c.Pos, c.Role, c.Subject, c.Key, c.Signature,
			c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"), left)
	}
	for _, f := range r.Findings {
		where := ""
		if f.Pos > 0 {
			where = fmt.Sprintf(" #%d", f.Pos)
		}
		fmt.Fprintf(&b, "  %-7s %s%s %s\n", f.Severity, f.ID, where, f.Message)
	}
	return b.String()
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
