package oidc

import (
	"context"
	"errors"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	"github.com/abinnovision/oidc-token-cli/internal/oidctest"
)

func TestRefresh_Success_RotatesToken(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.IncludeIDToken = true

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	res, err := p.Refresh(context.Background(), "openid offline_access", "old-refresh-token")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
	if res.RefreshToken == "" || res.RefreshToken == "old-refresh-token" {
		t.Fatalf("expected a rotated refresh_token, got %q", res.RefreshToken)
	}
	if res.IDToken == "" {
		t.Fatal("expected a verified id_token")
	}
}

func TestRefresh_InvalidGrant_Errors(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.RefreshErr = "invalid_grant"

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	_, err = p.Refresh(context.Background(), "openid offline_access", "revoked-refresh-token")
	if err == nil {
		t.Fatal("expected an error when the issuer rejects the refresh token")
	}
}

func TestRefresh_ClientSecretBasic_Success(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.RequireClientAuth = "client_secret_basic"
	m.ExpectedClientSecret = "s3cr3t"

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	p.SetClientAuth(ClientAuthSecretBasic, "s3cr3t", nil, "", "", "")

	res, err := p.Refresh(context.Background(), "openid offline_access", "old-refresh-token")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
}

func TestRefresh_ClientSecretBasic_WrongSecret_Rejected(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.RequireClientAuth = "client_secret_basic"
	m.ExpectedClientSecret = "s3cr3t"

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	p.SetClientAuth(ClientAuthSecretBasic, "wrong-secret", nil, "", "", "")

	_, err = p.Refresh(context.Background(), "openid offline_access", "old-refresh-token")
	if err == nil {
		t.Fatal("expected an error for a mismatched client_secret")
	}
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) {
		t.Fatalf("expected a wrapped *oauth2.RetrieveError, got %v", err)
	}
	if re.ErrorCode != "invalid_client" {
		t.Fatalf("expected error code invalid_client, got %q", re.ErrorCode)
	}
}

func TestRefresh_ClientSecretPost_Success(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.RequireClientAuth = "client_secret_post"
	m.ExpectedClientSecret = "s3cr3t"

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	p.SetClientAuth(ClientAuthSecretPost, "s3cr3t", nil, "", "", "")

	res, err := p.Refresh(context.Background(), "openid offline_access", "old-refresh-token")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
}

func TestRefresh_PrivateKeyJWT_Success(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.IncludeIDToken = true
	key := generateTestKey(t)
	m.RequireClientAuth = "private_key_jwt"
	m.ExpectedAssertionKey = &key.PublicKey

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	p.SetClientAuth(ClientAuthPrivateKeyJWT, "", key, "", jose.RS256, "")

	res, err := p.Refresh(context.Background(), "openid offline_access", "old-refresh-token")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
	if res.RefreshToken == "" || res.RefreshToken == "old-refresh-token" {
		t.Fatalf("expected a rotated refresh_token, got %q", res.RefreshToken)
	}
	if res.IDToken == "" {
		t.Fatal("expected a verified id_token")
	}
	if len(m.AssertionJTIs()) != 1 {
		t.Fatalf("expected exactly one verified client assertion, got %d", len(m.AssertionJTIs()))
	}
}

func TestRefresh_PrivateKeyJWT_WrongKey_Rejected(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	signingKey := generateTestKey(t)
	otherKey := generateTestKey(t)
	m.RequireClientAuth = "private_key_jwt"
	m.ExpectedAssertionKey = &otherKey.PublicKey // mock verifies against a different key than the one signing

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	p.SetClientAuth(ClientAuthPrivateKeyJWT, "", signingKey, "", jose.RS256, "")

	_, err = p.Refresh(context.Background(), "openid offline_access", "old-refresh-token")
	if err == nil {
		t.Fatal("expected an error for an assertion signed with the wrong key")
	}
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) {
		t.Fatalf("expected a wrapped *oauth2.RetrieveError, got %v", err)
	}
}
