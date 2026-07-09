//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"testing"

	"github.com/abinnovision/oidc-token-cli/internal/authflow"
	"github.com/abinnovision/oidc-token-cli/internal/cache"
	"github.com/abinnovision/oidc-token-cli/internal/config"
	"github.com/abinnovision/oidc-token-cli/internal/runner"
)

// TestE2E_AuthCodePKCE_EndToEnd_ViaRunner drives the full runner.Runner +
// authflow.Source(GrantAuthCode) stack against a real dex instance, with
// dex's actual local-connector login form scripted via dexLoginWalker
// instead of a real browser. Proves the id_token verifies against dex's
// real JWKS, not go-jose-signed fixtures.
func TestE2E_AuthCodePKCE_EndToEnd_ViaRunner(t *testing.T) {
	dex := StartDex(t)

	cfg := &config.Config{Issuer: dex.IssuerURL, ClientID: dex.ClientID, TokenType: config.TokenTypeIDToken}
	var prompt bytes.Buffer
	src := &authflow.Source{
		Issuer:       cfg.Issuer,
		ClientID:     cfg.ClientID,
		Scope:        "openid offline_access",
		GrantType:    authflow.GrantAuthCode,
		CallbackPort: dex.RedirectPort,
		Env:          authflow.Environment{TTY: true, Display: true},
		OpenBrowser:  dexLoginWalker(t, dex.Username, dex.Password),
		Prompt:       &prompt,
	}
	rnr := &runner.Runner{Cache: cache.New(t.TempDir()), Source: src, Config: cfg, Stderr: &prompt}

	res, err := rnr.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v (prompt: %s)", err, prompt.String())
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
	if res.IDToken == "" {
		t.Fatal("expected a non-empty id_token")
	}
	if res.IDTokenError != nil {
		t.Fatalf("id_token failed real-JWKS verification: %v", res.IDTokenError)
	}
}
