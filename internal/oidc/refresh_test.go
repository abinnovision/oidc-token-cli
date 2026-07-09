package oidc

import (
	"context"
	"testing"

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
