package authflow

import (
	"strings"
	"testing"
)

// TestOpenBrowser_RejectsNonHTTPScheme guards against a compromised
// discovery response smuggling non-http(s) content into exec.Command.
func TestOpenBrowser_RejectsNonHTTPScheme(t *testing.T) {
	cases := []string{
		"javascript:alert(1)",
		"file:///etc/passwd",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
	}
	for _, u := range cases {
		if err := OpenBrowser(u); err == nil {
			t.Errorf("OpenBrowser(%q) = nil error, want a refusal", u)
		}
	}
}

func TestOpenBrowser_RejectsInvalidURL(t *testing.T) {
	if err := OpenBrowser("://not a url"); err == nil {
		t.Fatal("expected an error for an unparseable URL")
	}
}

func TestOpenBrowser_AcceptsHTTPS(t *testing.T) {
	// Don't assert success (would try launching a browser in CI); just
	// confirm the scheme check doesn't reject it.
	err := OpenBrowser("https://issuer.example/authorize?client_id=x")
	if err != nil && strings.Contains(err.Error(), "refusing") {
		t.Fatalf("a valid https:// URL must not be refused by scheme validation, got: %v", err)
	}
}
