package main

import (
	"os"
	"testing"

	"github.com/abinnovision/oidc-token-cli/internal/authflow"
	"github.com/abinnovision/oidc-token-cli/internal/config"
)

// TestNewRealSource_PromptIsStderrNotStdout guards against the prompt
// (verification URLs, user codes) ever getting wired to stdout, which is
// reserved for the final token bytes written by run() in main.go.
func TestNewRealSource_PromptIsStderrNotStdout(t *testing.T) {
	cfg := &config.Config{Issuer: "https://issuer.example", ClientID: "cid"}
	src, ok := newRealSource(cfg).(*authflow.Source)
	if !ok {
		t.Fatalf("newRealSource returned %T, want *authflow.Source", newRealSource(cfg))
	}
	if src.Prompt != os.Stderr {
		t.Fatalf("Source.Prompt = %v, want os.Stderr", src.Prompt)
	}
}
