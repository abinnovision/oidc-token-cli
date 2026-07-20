package config

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

// allFlagNames lists every flag oidc-token registers, mirroring config.go's
// Parse plus the grant packages' RegisterFlags, so the grouping tests can
// build a representative FlagSet without importing the full grant wiring.
var allFlagNames = []string{
	"issuer", "client-id", "scope", "audience", "grant-type", "token-type",
	"config", "all", "logout", "non-interactive",
	"token-store", "token-store-dir",
	"client-auth-method", "client-secret", "client-secret-file",
	"private-key-file", "private-key-id", "private-key-alg", "client-assertion-audience",
	"subject-token", "subject-token-file", "subject-token-type", "subject-token-source",
	"requested-token-type", "resource",
	"redirect", "extra",
}

// newTestFlagSet registers every flag oidc-token exposes, using the same
// stdlib flag constructors config.go and the grant packages use, so
// printGroupedUsage sees a representative FlagSet.
func newTestFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("oidc-token", flag.ContinueOnError)
	for _, name := range allFlagNames {
		switch name {
		case "all", "logout", "non-interactive":
			fs.Bool(name, false, "usage for "+name)
		case "redirect":
			fs.Int(name, 0, "usage for "+name)
		default:
			fs.String(name, "", "usage for "+name)
		}
	}
	return fs
}

func TestGroupedUsage_AllFlagsPresent(t *testing.T) {
	fs := newTestFlagSet()
	var buf bytes.Buffer
	printGroupedUsage(&buf, fs)
	out := buf.String()

	fs.VisitAll(func(f *flag.Flag) {
		if !strings.Contains(out, "-"+f.Name) {
			t.Errorf("printGroupedUsage output missing flag %q\noutput:\n%s", f.Name, out)
		}
	})
}

func TestGroupedUsage_GroupOrder(t *testing.T) {
	fs := newTestFlagSet()
	var buf bytes.Buffer
	printGroupedUsage(&buf, fs)
	out := buf.String()

	var lastIdx = -1
	for _, g := range groups {
		idx := strings.Index(out, g.Title+":")
		if idx == -1 {
			t.Fatalf("group title %q not found in output:\n%s", g.Title, out)
		}
		if idx <= lastIdx {
			t.Errorf("group %q at index %d appears out of order (previous group ended at %d)", g.Title, idx, lastIdx)
		}
		lastIdx = idx
	}
}

func TestGroupedUsage_UngroupedFallback(t *testing.T) {
	fs := newTestFlagSet()
	fs.String("unknown-flag", "", "an ungrouped flag")

	var buf bytes.Buffer
	printGroupedUsage(&buf, fs)
	out := buf.String()

	if !strings.Contains(out, "Other:") {
		t.Errorf("expected \"Other:\" section in output:\n%s", out)
	}
	if !strings.Contains(out, "unknown-flag") {
		t.Errorf("expected \"unknown-flag\" in output:\n%s", out)
	}
}
