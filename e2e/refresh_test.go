//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/abinnovision/oidc-token-cli/internal/authflow"
	"github.com/abinnovision/oidc-token-cli/internal/cache"
	"github.com/abinnovision/oidc-token-cli/internal/config"
	"github.com/abinnovision/oidc-token-cli/internal/runner"
)

// TestE2E_RefreshToken_EndToEnd seeds the cache with a real (deliberately
// expired) access token and a real refresh_token obtained from dex, then
// runs the runner again to trigger an actual refresh_token grant — proving
// dex's real rotation behavior doesn't break the runner, not just the
// mock's configurable OmitRefreshToken/RefreshDelay knobs.
func TestE2E_RefreshToken_EndToEnd(t *testing.T) {
	dex := StartDex(t)

	cfg := &config.Config{Issuer: dex.IssuerURL, ClientID: dex.ClientID}
	c := cache.New(t.TempDir())

	// Seed step: a real authcode login against dex to obtain a genuine
	// refresh_token.
	var seedPrompt bytes.Buffer
	seedSrc := &authflow.Source{
		Issuer:       cfg.Issuer,
		ClientID:     cfg.ClientID,
		Scope:        "openid offline_access",
		GrantType:    authflow.GrantAuthCode,
		CallbackPort: dex.RedirectPort,
		Env:          authflow.Environment{TTY: true, Display: true},
		OpenBrowser:  dexLoginWalker(t, dex.Username, dex.Password),
		Prompt:       &seedPrompt,
	}
	seedRnr := &runner.Runner{Cache: c, Source: seedSrc, Config: cfg, Stderr: &seedPrompt}
	seedRes, err := seedRnr.Run(context.Background())
	if err != nil {
		t.Fatalf("seed login: %v (prompt: %s)", err, seedPrompt.String())
	}
	if seedRes.RefreshToken == "" {
		t.Fatal("expected dex to return a refresh_token for the openid offline_access scope")
	}

	// Force the cached entry to look expired so Run() takes the silent
	// refresh path instead of the still-valid cache hit.
	if err := c.Save(context.Background(), cache.Entry{
		Issuer:       cfg.Issuer,
		ClientID:     cfg.ClientID,
		AccessToken:  seedRes.AccessToken,
		IDToken:      seedRes.IDToken,
		RefreshToken: seedRes.RefreshToken,
		Expiry:       time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	var prompt bytes.Buffer
	src := &authflow.Source{Issuer: cfg.Issuer, ClientID: cfg.ClientID, Scope: "openid offline_access", Prompt: &prompt}
	rnr := &runner.Runner{Cache: c, Source: src, Config: cfg, Stderr: &prompt}

	res, err := rnr.Run(context.Background())
	if err != nil {
		t.Fatalf("Run (refresh): %v (prompt: %s)", err, prompt.String())
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty refreshed access_token")
	}
	if res.AccessToken == seedRes.AccessToken {
		t.Fatal("expected the refresh grant to mint a new access_token, got the seeded one back")
	}
	if prompt.Len() != 0 {
		t.Fatalf("silent refresh must never print an interactive prompt, got: %q", prompt.String())
	}
}
