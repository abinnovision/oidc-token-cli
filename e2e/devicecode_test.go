//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"io"
	"regexp"
	"sync"
	"testing"

	"github.com/abinnovision/oidc-token-cli/internal/authflow"
	"github.com/abinnovision/oidc-token-cli/internal/cache"
	"github.com/abinnovision/oidc-token-cli/internal/config"
	"github.com/abinnovision/oidc-token-cli/internal/oidc"
	"github.com/abinnovision/oidc-token-cli/internal/runner"
)

var deviceVerifyURLRe = regexp.MustCompile(`https?://\S+`)

// deviceURLCatcher forwards every write to an underlying io.Writer while
// watching for the device-code verification URL DeviceLogin prints; once
// found, it fires onURL exactly once, off the writer goroutine so it never
// blocks DeviceLogin's own poll loop.
type deviceURLCatcher struct {
	underlying io.Writer
	onURL      func(string)

	mu    sync.Mutex
	fired bool
}

func (c *deviceURLCatcher) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.fired {
		if m := deviceVerifyURLRe.Find(p); m != nil {
			c.fired = true
			url := string(m)
			go c.onURL(url)
		}
	}
	c.mu.Unlock()
	return c.underlying.Write(p)
}

// TestE2E_DeviceCode_EndToEnd drives runner.Runner + authflow.Source
// (GrantDeviceCode) against real dex, scripting the verification URL with
// dexLoginWalker concurrently with the CLI's own poll loop. Skips
// gracefully if the pinned dex image doesn't advertise
// device_authorization_endpoint, since dex's device-flow support/behavior
// with public clients (dexidp/dex#3983) isn't guaranteed stable.
func TestE2E_DeviceCode_EndToEnd(t *testing.T) {
	dex := StartDex(t)

	p, err := oidc.Discover(context.Background(), dex.IssuerURL, dex.ClientID)
	if err != nil {
		t.Fatalf("oidc.Discover: %v", err)
	}
	if !p.SupportsDeviceCode() {
		t.Skip("e2e: pinned dex image does not advertise device_authorization_endpoint")
	}

	cfg := &config.Config{Issuer: dex.IssuerURL, ClientID: dex.ClientID}
	var prompt bytes.Buffer
	walker := dexLoginWalker(t, dex.Username, dex.Password)
	catcher := &deviceURLCatcher{underlying: &prompt, onURL: func(url string) { _ = walker(url) }}

	src := &authflow.Source{
		Issuer:    cfg.Issuer,
		ClientID:  cfg.ClientID,
		Scope:     "openid offline_access",
		GrantType: authflow.GrantDeviceCode,
		Env:       authflow.Environment{TTY: true, Display: false},
		Prompt:    catcher,
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
