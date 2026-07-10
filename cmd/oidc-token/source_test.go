package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

// TestResolveRealSubjectToken_GitHubActions_DelegatesToSubjectTokenPackage
// exercises resolveRealSubjectToken's wiring (env vars, cfg.Audience) via
// real process env vars pointed at a local test server, without
// re-testing subjecttoken.FetchGitHubActions's own internals.
func TestResolveRealSubjectToken_GitHubActions_DelegatesToSubjectTokenPackage(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"value":"jwt-from-github-actions"}`))
	}))
	defer srv.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req-token")

	cfg := &config.Config{
		Issuer:             "https://issuer.example",
		ClientID:           "cid",
		Audience:           "gtb-abinnovision",
		SubjectTokenSource: config.SubjectTokenSourceGitHubActions,
	}

	token, err := resolveRealSubjectToken(context.Background(), cfg)
	if err != nil {
		t.Fatalf("resolveRealSubjectToken: %v", err)
	}
	if token != "jwt-from-github-actions" {
		t.Fatalf("token = %q, want %q", token, "jwt-from-github-actions")
	}
	if !strings.Contains(gotQuery, "audience=gtb-abinnovision") {
		t.Fatalf("query = %q, want cfg.Audience passed through as the audience param", gotQuery)
	}
}

func TestResolveRealSubjectToken_UnsupportedSource_Errors(t *testing.T) {
	cfg := &config.Config{
		Issuer:             "https://issuer.example",
		ClientID:           "cid",
		SubjectTokenSource: config.SubjectTokenSource("unsupported"),
	}
	if _, err := resolveRealSubjectToken(context.Background(), cfg); err == nil {
		t.Fatal("expected an error for an unsupported SubjectTokenSource")
	}
}
