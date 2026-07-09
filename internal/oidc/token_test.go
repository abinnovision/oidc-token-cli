package oidc

import (
	"context"
	"testing"

	"golang.org/x/oauth2"

	"github.com/abinnovision/oidc-token-cli/internal/oidctest"
)

// TestToResult_AccessTokenNeverFedToIDTokenVerifier guards against toResult
// ever verifying AccessToken instead of the "id_token" extra field: an
// opaque non-JWT access_token with no id_token present must produce a
// clean result with no IDTokenError.
func TestToResult_AccessTokenNeverFedToIDTokenVerifier(t *testing.T) {
	m := oidctest.NewMockIssuer(t)

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	tok := &oauth2.Token{AccessToken: "opaque-not-a-jwt-at-all"}
	res, err := p.toResult(context.Background(), tok, "")
	if err != nil {
		t.Fatalf("toResult: %v", err)
	}
	if res.IDTokenError != nil {
		t.Fatalf("IDTokenError = %v, want nil: the access_token must never be fed to the id_token verifier", res.IDTokenError)
	}
	if res.IDToken != "" {
		t.Fatalf("IDToken = %q, want empty when no id_token was present in the response", res.IDToken)
	}
	if res.AccessToken != "opaque-not-a-jwt-at-all" {
		t.Fatalf("AccessToken = %q, want passthrough of the opaque access_token", res.AccessToken)
	}
}
