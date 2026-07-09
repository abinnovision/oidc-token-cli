//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"testing"

	"github.com/abinnovision/oidc-token-cli/internal/authflow"
	"github.com/abinnovision/oidc-token-cli/internal/cache"
	"github.com/abinnovision/oidc-token-cli/internal/config"
	"github.com/abinnovision/oidc-token-cli/internal/oidc"
	"github.com/abinnovision/oidc-token-cli/internal/runner"
)

// TestE2E_AuthCode_ClientSecretBasic_EndToEnd drives the authcode+PKCE flow
// against dex's second, confidential static client, authenticating to the
// token endpoint with client_secret_basic (HTTP Basic auth) -- proving the
// real request round-trips against dex's actual token-endpoint client-auth
// handling, not just the mock issuer's.
func TestE2E_AuthCode_ClientSecretBasic_EndToEnd(t *testing.T) {
	dex := StartDex(t)

	cfg := &config.Config{Issuer: dex.IssuerURL, ClientID: dex.ConfidentialClientID}
	var prompt bytes.Buffer
	src := &authflow.Source{
		Issuer:           cfg.Issuer,
		ClientID:         cfg.ClientID,
		Scope:            "openid offline_access",
		GrantType:        authflow.GrantAuthCode,
		CallbackPort:     dex.RedirectPort,
		Env:              authflow.Environment{TTY: true, Display: true},
		OpenBrowser:      dexLoginWalker(t, dex.Username, dex.Password),
		Prompt:           &prompt,
		ClientAuthMethod: oidc.ClientAuthSecretBasic,
		ClientSecret:     dex.ConfidentialClientSecret,
	}
	rnr := &runner.Runner{Cache: cache.New(t.TempDir()), Source: src, Config: cfg, Stderr: &prompt}

	res, err := rnr.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v (prompt: %s)", err, prompt.String())
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
}

// TestE2E_AuthCode_ClientSecretBasic_WrongSecret_Rejected proves dex
// actually enforces the secret it was configured with, rather than the
// success case above merely reflecting a no-op auth check.
func TestE2E_AuthCode_ClientSecretBasic_WrongSecret_Rejected(t *testing.T) {
	dex := StartDex(t)

	cfg := &config.Config{Issuer: dex.IssuerURL, ClientID: dex.ConfidentialClientID}
	var prompt bytes.Buffer
	src := &authflow.Source{
		Issuer:           cfg.Issuer,
		ClientID:         cfg.ClientID,
		Scope:            "openid offline_access",
		GrantType:        authflow.GrantAuthCode,
		CallbackPort:     dex.RedirectPort,
		Env:              authflow.Environment{TTY: true, Display: true},
		OpenBrowser:      dexLoginWalker(t, dex.Username, dex.Password),
		Prompt:           &prompt,
		ClientAuthMethod: oidc.ClientAuthSecretBasic,
		ClientSecret:     "wrong-secret",
	}
	rnr := &runner.Runner{Cache: cache.New(t.TempDir()), Source: src, Config: cfg, Stderr: &prompt}

	if _, err := rnr.Run(context.Background()); err == nil {
		t.Fatal("expected dex to reject a mismatched client_secret")
	}
}

// TestE2E_AuthCode_ClientSecretPost_EndToEnd is the client_secret_post
// counterpart of TestE2E_AuthCode_ClientSecretBasic_EndToEnd: same
// confidential client, secret sent as a POST body param instead of an
// Authorization header.
func TestE2E_AuthCode_ClientSecretPost_EndToEnd(t *testing.T) {
	dex := StartDex(t)

	cfg := &config.Config{Issuer: dex.IssuerURL, ClientID: dex.ConfidentialClientID}
	var prompt bytes.Buffer
	src := &authflow.Source{
		Issuer:           cfg.Issuer,
		ClientID:         cfg.ClientID,
		Scope:            "openid offline_access",
		GrantType:        authflow.GrantAuthCode,
		CallbackPort:     dex.RedirectPort,
		Env:              authflow.Environment{TTY: true, Display: true},
		OpenBrowser:      dexLoginWalker(t, dex.Username, dex.Password),
		Prompt:           &prompt,
		ClientAuthMethod: oidc.ClientAuthSecretPost,
		ClientSecret:     dex.ConfidentialClientSecret,
	}
	rnr := &runner.Runner{Cache: cache.New(t.TempDir()), Source: src, Config: cfg, Stderr: &prompt}

	res, err := rnr.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v (prompt: %s)", err, prompt.String())
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
}
