//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/abinnovision/oidc-token-cli/internal/authflow"
	"github.com/abinnovision/oidc-token-cli/internal/oidc"
	"github.com/abinnovision/oidc-token-cli/internal/oidctest"
)

// Token-exchange e2e coverage uses oidctest.MockIssuer rather than
// StartDex: dex v2.42.0's token-exchange support is a connector-scoped
// "upstream token exchange" (mandatory connector_id, subject_token must be
// issued by a configured upstream connector), which is incompatible with
// this CLI's generic subject_token/subject_token_type design -- see the
// doc comment on dexImage in dex_container.go.

// TestE2E_TokenExchange_ClientSecretBasic_EndToEnd drives a full discovery
// -> token-exchange request -> response-parsing round-trip, authenticating
// to the token endpoint with client_secret_basic.
func TestE2E_TokenExchange_ClientSecretBasic_EndToEnd(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.RequireClientAuth = "client_secret_basic"
	m.ExpectedClientSecret = "s3cr3t"

	var prompt bytes.Buffer
	src := &authflow.Source{
		Issuer:           m.Issuer(),
		ClientID:         oidctest.ClientID,
		Scope:            "openid",
		Prompt:           &prompt,
		ClientAuthMethod: oidc.ClientAuthSecretBasic,
		ClientSecret:     "s3cr3t",
	}

	res, err := src.TokenExchange(context.Background(), "subject-token-value", "urn:ietf:params:oauth:token-type:access_token", "", nil)
	if err != nil {
		t.Fatalf("TokenExchange: %v (prompt: %s)", err, prompt.String())
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
}

// TestE2E_TokenExchange_PrivateKeyJWT_EndToEnd is the private_key_jwt
// counterpart, proving the client-assertion path works end to end for
// token exchange too, not just refresh/authcode.
func TestE2E_TokenExchange_PrivateKeyJWT_EndToEnd(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	m.RequireClientAuth = "private_key_jwt"
	m.ExpectedAssertionKey = &key.PublicKey

	var prompt bytes.Buffer
	src := &authflow.Source{
		Issuer:               m.Issuer(),
		ClientID:             oidctest.ClientID,
		Scope:                "openid",
		Prompt:               &prompt,
		ClientAuthMethod:     oidc.ClientAuthPrivateKeyJWT,
		PrivateKey:           key,
		PrivateKeySigningAlg: jose.RS256,
	}

	res, err := src.TokenExchange(context.Background(), "subject-token-value", "urn:ietf:params:oauth:token-type:access_token", "", nil)
	if err != nil {
		t.Fatalf("TokenExchange: %v (prompt: %s)", err, prompt.String())
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
	if len(m.AssertionJTIs()) != 1 {
		t.Fatalf("expected exactly one verified client assertion, got %d", len(m.AssertionJTIs()))
	}
}
