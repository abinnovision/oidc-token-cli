package oidc

import (
	"context"
	"errors"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	"github.com/abinnovision/oidc-token-cli/internal/oidctest"
)

const testSubjectTokenType = "urn:ietf:params:oauth:token-type:access_token"

func TestTokenExchange_Success_ReturnsAccessToken(t *testing.T) {
	m := oidctest.NewMockIssuer(t)

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	res, err := p.TokenExchange(context.Background(), "openid", "subject-token-value", testSubjectTokenType, "", nil)
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
}

func TestTokenExchange_IncludesIssuedTokenType(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.IssuedTokenType = "urn:ietf:params:oauth:token-type:jwt"

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	res, err := p.TokenExchange(context.Background(), "", "subject-token-value", testSubjectTokenType, "", nil)
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if res.IssuedTokenType != "urn:ietf:params:oauth:token-type:jwt" {
		t.Fatalf("IssuedTokenType = %q, want the mock's configured value", res.IssuedTokenType)
	}
}

func TestTokenExchange_ClientSecretBasic_Success(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.RequireClientAuth = "client_secret_basic"
	m.ExpectedClientSecret = "s3cr3t"

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	p.SetClientAuth(ClientAuthSecretBasic, "s3cr3t", nil, "", "", "")

	res, err := p.TokenExchange(context.Background(), "", "subject-token-value", testSubjectTokenType, "", nil)
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
}

func TestTokenExchange_ClientSecretPost_Success(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.RequireClientAuth = "client_secret_post"
	m.ExpectedClientSecret = "s3cr3t"

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	p.SetClientAuth(ClientAuthSecretPost, "s3cr3t", nil, "", "", "")

	res, err := p.TokenExchange(context.Background(), "", "subject-token-value", testSubjectTokenType, "", nil)
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
}

func TestTokenExchange_PrivateKeyJWT_Success(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	key := generateTestKey(t)
	m.RequireClientAuth = "private_key_jwt"
	m.ExpectedAssertionKey = &key.PublicKey

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	p.SetClientAuth(ClientAuthPrivateKeyJWT, "", key, "", jose.RS256, "")

	res, err := p.TokenExchange(context.Background(), "", "subject-token-value", testSubjectTokenType, "", nil)
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
	if len(m.AssertionJTIs()) != 1 {
		t.Fatalf("expected exactly one verified client assertion, got %d", len(m.AssertionJTIs()))
	}
}

func TestTokenExchange_PrivateKeyJWT_WrongKey_Rejected(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	signingKey := generateTestKey(t)
	otherKey := generateTestKey(t)
	m.RequireClientAuth = "private_key_jwt"
	m.ExpectedAssertionKey = &otherKey.PublicKey

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	p.SetClientAuth(ClientAuthPrivateKeyJWT, "", signingKey, "", jose.RS256, "")

	_, err = p.TokenExchange(context.Background(), "", "subject-token-value", testSubjectTokenType, "", nil)
	if err == nil {
		t.Fatal("expected an error for an assertion signed with the wrong key")
	}
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) {
		t.Fatalf("expected a wrapped *oauth2.RetrieveError, got %v", err)
	}
}

func TestTokenExchange_SendsAudienceWhenSet(t *testing.T) {
	m := oidctest.NewMockIssuer(t)

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	p.SetAudience("https://api.example/")

	if _, err := p.TokenExchange(context.Background(), "", "subject-token-value", testSubjectTokenType, "", nil); err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if got := m.LastTokenExchangeRequest().Get("audience"); got != "https://api.example/" {
		t.Fatalf("audience = %q, want the configured audience", got)
	}
}

func TestTokenExchange_OmitsAudienceWhenUnset(t *testing.T) {
	m := oidctest.NewMockIssuer(t)

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if _, err := p.TokenExchange(context.Background(), "", "subject-token-value", testSubjectTokenType, "", nil); err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if _, ok := m.LastTokenExchangeRequest()["audience"]; ok {
		t.Fatal("expected no audience param when unset")
	}
}

func TestTokenExchange_OmitsRequestedTokenTypeWhenUnset(t *testing.T) {
	m := oidctest.NewMockIssuer(t)

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if _, err := p.TokenExchange(context.Background(), "", "subject-token-value", testSubjectTokenType, "", nil); err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if _, ok := m.LastTokenExchangeRequest()["requested_token_type"]; ok {
		t.Fatal("expected no requested_token_type param when unset")
	}
}

func TestTokenExchange_SendsMultipleResourceParams(t *testing.T) {
	m := oidctest.NewMockIssuer(t)

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	resources := []string{"https://a.example/", "https://b.example/"}
	if _, err := p.TokenExchange(context.Background(), "", "subject-token-value", testSubjectTokenType, "", resources); err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	got := m.LastTokenExchangeRequest()["resource"]
	if len(got) != 2 || got[0] != resources[0] || got[1] != resources[1] {
		t.Fatalf("resource params = %v, want %v", got, resources)
	}
}

func TestTokenExchange_InvalidGrant_Errors(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.TokenExchangeErr = "invalid_grant"

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	_, err = p.TokenExchange(context.Background(), "", "subject-token-value", testSubjectTokenType, "", nil)
	if err == nil {
		t.Fatal("expected an error when the issuer rejects the subject token")
	}
}
