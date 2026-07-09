//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/abinnovision/oidc-token-cli/internal/authflow"
	"github.com/abinnovision/oidc-token-cli/internal/cache"
	"github.com/abinnovision/oidc-token-cli/internal/config"
	"github.com/abinnovision/oidc-token-cli/internal/runner"
)

// TestE2E_InvalidCredentials_LoginFails submits a wrong password through
// dex's real login form. Unlike an issuer that rejects the client itself
// (an oauth "error=" redirect), a failed *password* submission just
// re-renders dex's login page — the authorization flow never completes, so
// the CLI's loopback callback times out. A short context deadline bounds
// the wait; the test asserts the runner surfaces that failure through
// runner.ErrLoginFailed rather than hanging for the default 5-minute
// authcode timeout.
func TestE2E_InvalidCredentials_LoginFails(t *testing.T) {
	dex := StartDex(t)

	cfg := &config.Config{Issuer: dex.IssuerURL, ClientID: dex.ClientID}
	var prompt bytes.Buffer
	src := &authflow.Source{
		Issuer:       cfg.Issuer,
		ClientID:     cfg.ClientID,
		Scope:        "openid offline_access",
		GrantType:    authflow.GrantAuthCode,
		CallbackPort: dex.RedirectPort,
		Env:          authflow.Environment{TTY: true, Display: true},
		OpenBrowser:  dexLoginWalker(t, dex.Username, "definitely-the-wrong-password"),
		Prompt:       &prompt,
	}
	rnr := &runner.Runner{Cache: cache.New(t.TempDir()), Source: src, Config: cfg, Stderr: &prompt}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := rnr.Run(ctx)
	if err == nil {
		t.Fatal("expected an error for a wrong-password login")
	}
	if !errors.Is(err, runner.ErrLoginFailed) {
		t.Fatalf("error = %v, want it to wrap runner.ErrLoginFailed", err)
	}
	if !strings.Contains(err.Error(), "timed out waiting for the authorization callback") {
		t.Fatalf("error = %v, want it to explain the callback never arrived", err)
	}
}
