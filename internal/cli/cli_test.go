package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC) }

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, &out, &errb, fixedNow)
	return code, out.String(), errb.String()
}

const td = "../../testdata/"

func TestACleanChainExitsZero(t *testing.T) {
	code, out, _ := run(t, td+"fullchain.pem")
	if code != 0 || !strings.Contains(out, "2 certificates, no findings") {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func TestAnErrorExitsOne(t *testing.T) {
	code, out, _ := run(t, td+"expired.pem")
	if code != 1 || !strings.Contains(out, "CW001") {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func TestWarningsFailOnlyUnderStrict(t *testing.T) {
	if code, _, _ := run(t, td+"wrong-order.pem"); code != 0 {
		t.Fatalf("a warning alone should exit 0, got %d", code)
	}
	if code, _, _ := run(t, "--strict", td+"wrong-order.pem"); code != 1 {
		t.Fatalf("--strict should exit 1, got %d", code)
	}
}

func TestFlagsMayFollowThePaths(t *testing.T) {
	code, out, _ := run(t, td+"wrong-order.pem", "--strict", "--json")
	if code != 1 || !strings.HasPrefix(out, "[") {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func TestNowChangesTheVerdict(t *testing.T) {
	if code, _, _ := run(t, "--now", "2026-12-20T00:00:00Z", td+"fullchain.pem"); code != 1 {
		t.Fatalf("after the leaf's expiry the chain should fail, got %d", code)
	}
	if code, out, _ := run(t, "--now", "2026-11-25T00:00:00Z", "--strict", td+"fullchain.pem"); code != 1 || !strings.Contains(out, "CW002") {
		t.Fatalf("14 days before expiry should warn: %d\n%s", code, out)
	}
	if code, _, _ := run(t, "--now", "2026-11-25T00:00:00Z", "--warn-days", "10", "--strict", td+"fullchain.pem"); code != 0 {
		t.Fatalf("a 10-day threshold should not warn at 14 days left, got %d", code)
	}
}

func TestJSONIsValidAndComplete(t *testing.T) {
	code, out, _ := run(t, "--json", td+"missing-intermediate.pem", td+"fullchain.pem")
	if code != 1 {
		t.Fatalf("code %d", code)
	}
	var reports []struct {
		Path         string `json:"path"`
		Certificates []struct {
			Role   string `json:"role"`
			SHA256 string `json:"sha256"`
		} `json:"certificates"`
		Findings []struct {
			ID, Severity string
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &reports); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(reports) != 2 || len(reports[0].Certificates) != 2 || len(reports[0].Certificates[0].SHA256) != 64 {
		t.Fatalf("%+v", reports)
	}
}

func TestUsageErrorsExitTwo(t *testing.T) {
	for name, args := range map[string][]string{
		"no paths":     {},
		"unknown flag": {"--nope", td + "fullchain.pem"},
		"bad now":      {"--now", "yesterday", td + "fullchain.pem"},
		"missing file": {filepath.Join(t.TempDir(), "nope.pem")},
		"bad days":     {"--warn-days", "-1", td + "fullchain.pem"},
	} {
		if code, _, errOut := run(t, args...); code != 2 || errOut == "" {
			t.Errorf("%s: code %d, stderr %q", name, code, errOut)
		}
	}
}

func TestVersionAndHelp(t *testing.T) {
	if code, out, _ := run(t, "--version"); code != 0 || !strings.HasPrefix(out, "certwarden ") {
		t.Fatal(out)
	}
	if code, out, _ := run(t, "--help"); code != 0 || !strings.Contains(out, "usage:") {
		t.Fatal(out)
	}
}

func TestADirectoryWithNoCertificatesSaysSo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, dir)
	if code != 0 || !strings.Contains(out, "no certificate files found") {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func TestAGarbageFileFailsTheRun(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.pem")
	if err := os.WriteFile(p, []byte("-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := run(t, p); code != 1 || !strings.Contains(out, "CW071") {
		t.Fatalf("code %d\n%s", code, out)
	}
}
