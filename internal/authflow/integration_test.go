package authflow

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abinnovision/oidc-token-cli/internal/cache"
	"github.com/abinnovision/oidc-token-cli/internal/config"
	"github.com/abinnovision/oidc-token-cli/internal/oidctest"
	"github.com/abinnovision/oidc-token-cli/internal/runner"
)

// These tests exercise the real internal/oidc.Provider (via the default
// discoverFunc) against oidctest's mock issuer, wired through the real
// runner.Runner, proving the whole stack works together, not just each
// piece against a fake.

func newIntegrationRunner(t *testing.T, m *oidctest.MockIssuer, cfg *config.Config, prompt *bytes.Buffer) *runner.Runner {
	t.Helper()
	if cfg.Issuer == "" {
		cfg.Issuer = m.Issuer()
	}
	if cfg.ClientID == "" {
		cfg.ClientID = oidctest.ClientID
	}
	src := &Source{
		Issuer:    cfg.Issuer,
		ClientID:  cfg.ClientID,
		Scope:     "openid offline_access",
		GrantType: GrantDeviceCode,
		// Device-code needs a human at the terminal to read the user_code,
		// not a display.
		Env:            Environment{TTY: true, Display: false},
		NonInteractive: cfg.NonInteractive,
		Prompt:         prompt,
	}
	return &runner.Runner{
		Cache:  cache.New(t.TempDir()),
		Source: src,
		Config: cfg,
		Stderr: prompt,
	}
}

func TestIntegration_DeviceCode_EndToEnd_ViaRunner(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.IncludeIDToken = true

	var prompt bytes.Buffer
	cfg := &config.Config{}
	rnr := newIntegrationRunner(t, m, cfg, &prompt)

	res, err := rnr.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.AccessToken == "" || res.IDToken == "" {
		t.Fatalf("expected both access_token and id_token, got %+v", res)
	}
}

func TestIntegration_Auto_TerminalAttendedNoBrowser_UsesDeviceCode(t *testing.T) {
	m := oidctest.NewMockIssuer(t)

	var prompt bytes.Buffer
	cfg := &config.Config{}
	if cfg.Issuer == "" {
		cfg.Issuer = m.Issuer()
	}
	cfg.ClientID = oidctest.ClientID
	src := &Source{
		Issuer: cfg.Issuer, ClientID: cfg.ClientID, Scope: "openid",
		GrantType: GrantAuto, Env: Environment{TTY: true, Display: false},
		Prompt: &prompt,
	}
	rnr := &runner.Runner{Cache: cache.New(t.TempDir()), Source: src, Config: cfg, Stderr: &prompt}

	res, err := rnr.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a token via the auto-selected device-code grant")
	}
	if !bytes.Contains(prompt.Bytes(), []byte("USER-CODE")) {
		t.Fatalf("expected the device-code prompt (auto should have selected device-code headless), got: %q", prompt.String())
	}
}

func TestIntegration_Auto_Interactive_UsesAuthCode(t *testing.T) {
	m := oidctest.NewMockIssuer(t)

	cfg := &config.Config{Issuer: m.Issuer(), ClientID: oidctest.ClientID}
	var prompt bytes.Buffer
	src := &Source{
		Issuer: cfg.Issuer, ClientID: cfg.ClientID, Scope: "openid",
		GrantType: GrantAuto, Env: Environment{TTY: true, Display: true},
		OpenBrowser: func(u string) error {
			go func() {
				parsed, _ := url.Parse(u)
				cbURL, _ := url.Parse(parsed.Query().Get("redirect_uri"))
				q := cbURL.Query()
				q.Set("code", oidctest.MockAuthCode)
				q.Set("state", parsed.Query().Get("state"))
				cbURL.RawQuery = q.Encode()
				resp, err := http.Get(cbURL.String())
				if err == nil {
					_ = resp.Body.Close()
				}
			}()
			return nil
		},
		Prompt: &prompt,
	}
	rnr := &runner.Runner{Cache: cache.New(t.TempDir()), Source: src, Config: cfg, Stderr: &prompt}

	res, err := rnr.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a token via the auto-selected authcode grant")
	}
}

func TestIntegration_NearExpiry_SilentRefresh_UnderLock_NoPrompt(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.IncludeIDToken = true

	var prompt bytes.Buffer
	cfg := &config.Config{}
	rnr := newIntegrationRunner(t, m, cfg, &prompt)

	if err := rnr.Cache.Save(cache.Entry{
		Issuer: cfg.Issuer, ClientID: cfg.ClientID,
		AccessToken: "stale", RefreshToken: "seed-refresh-token",
		Expiry: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	res, err := rnr.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a refreshed access_token")
	}
	if m.RefreshCallCount() != 1 {
		t.Fatalf("refresh calls = %d, want exactly 1", m.RefreshCallCount())
	}
	if prompt.Len() != 0 {
		t.Fatalf("silent refresh must never print a device-code prompt, got: %q", prompt.String())
	}
}

func TestIntegration_ConcurrentRefresh_RotationRace_ExactlyOneRefresh(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.IncludeIDToken = true
	m.RefreshDelay = 100 * time.Millisecond

	dir := t.TempDir()
	cfg := &config.Config{Issuer: m.Issuer(), ClientID: oidctest.ClientID}

	seed := cache.New(dir)
	if err := seed.Save(cache.Entry{
		Issuer: cfg.Issuer, ClientID: cfg.ClientID,
		AccessToken: "stale", RefreshToken: "seed-refresh-token",
		Expiry: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	const n = 4
	var wg sync.WaitGroup
	results := make([]string, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			var prompt bytes.Buffer
			src := &Source{Issuer: cfg.Issuer, ClientID: cfg.ClientID, Scope: "openid offline_access", GrantType: GrantDeviceCode, Prompt: &prompt}
			rnr := &runner.Runner{Cache: cache.New(dir), Source: src, Config: cfg, Stderr: &prompt}
			res, err := rnr.Run(context.Background())
			results[i] = res.AccessToken
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: Run: %v", i, err)
		}
	}
	if m.RefreshCallCount() != 1 {
		t.Fatalf("refresh calls = %d, want exactly 1", m.RefreshCallCount())
	}
	for i := 1; i < n; i++ {
		if results[i] != results[0] {
			t.Fatalf("goroutine %d got a different token than goroutine 0: %q vs %q", i, results[i], results[0])
		}
	}
}

func TestIntegration_RefreshFails_FallsBackToDeviceLogin(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.IncludeIDToken = true
	m.RefreshErr = "invalid_grant"

	var prompt bytes.Buffer
	cfg := &config.Config{}
	rnr := newIntegrationRunner(t, m, cfg, &prompt)

	if err := rnr.Cache.Save(cache.Entry{
		Issuer: cfg.Issuer, ClientID: cfg.ClientID,
		AccessToken: "stale", RefreshToken: "revoked-refresh-token",
		Expiry: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	res, err := rnr.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected device-login fallback to yield a token")
	}
	if !bytes.Contains(prompt.Bytes(), []byte("USER-CODE")) {
		t.Fatalf("expected the device-code prompt after refresh failure, got: %q", prompt.String())
	}
}

func TestIntegration_RefreshFails_NonInteractive_FastFail(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.RefreshErr = "invalid_grant"

	var prompt bytes.Buffer
	cfg := &config.Config{NonInteractive: true}
	rnr := newIntegrationRunner(t, m, cfg, &prompt)

	if err := rnr.Cache.Save(cache.Entry{
		Issuer: cfg.Issuer, ClientID: cfg.ClientID,
		AccessToken: "stale", RefreshToken: "revoked-refresh-token",
		Expiry: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	_, err := rnr.Run(context.Background())
	if err == nil {
		t.Fatal("expected an error: refresh failed, and the explicit device-code grant isn't viable headless under --non-interactive")
	}
	if !errors.Is(err, runner.ErrLoginFailed) {
		t.Fatalf("error = %v, want wrapping runner.ErrLoginFailed", err)
	}
	if !strings.Contains(err.Error(), "no viable login method") && !strings.Contains(err.Error(), "requires an attended terminal") {
		t.Fatalf("error = %v, want it to explain the device-code grant isn't viable", err)
	}
	if prompt.Len() != 0 {
		t.Fatalf("must never print a prompt before failing fast, got: %q", prompt.String())
	}
}

func TestIntegration_NonInteractive_BrowserAvailable_AuthCodeStillAttempted(t *testing.T) {
	// frpc-exec shape: no TTY, but a display/browser is available and
	// --non-interactive is set. authcode must still be attempted (it only
	// needs a browser), complete, and cache the token.
	m := oidctest.NewMockIssuer(t)

	cfg := &config.Config{Issuer: m.Issuer(), ClientID: oidctest.ClientID, NonInteractive: true}
	var prompt bytes.Buffer
	opened := make(chan string, 1)
	src := &Source{
		Issuer: cfg.Issuer, ClientID: cfg.ClientID, Scope: "openid",
		GrantType:      GrantAuto,
		Env:            Environment{TTY: false, Display: true},
		NonInteractive: true,
		OpenBrowser: func(u string) error {
			opened <- u
			go func() {
				parsed, _ := url.Parse(u)
				cbURL, _ := url.Parse(parsed.Query().Get("redirect_uri"))
				q := cbURL.Query()
				q.Set("code", oidctest.MockAuthCode)
				q.Set("state", parsed.Query().Get("state"))
				cbURL.RawQuery = q.Encode()
				resp, err := http.Get(cbURL.String())
				if err == nil {
					_ = resp.Body.Close()
				}
			}()
			return nil
		},
		Prompt: &prompt,
	}
	rnr := &runner.Runner{Cache: cache.New(t.TempDir()), Source: src, Config: cfg, Stderr: &prompt}

	res, err := rnr.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a token via the authcode grant despite --non-interactive")
	}
	select {
	case <-opened:
	default:
		t.Fatal("expected the browser opener to be invoked")
	}
}

func TestIntegration_NonInteractive_NoBrowser_ImmediateFailWithNegotiatedReasons(t *testing.T) {
	m := oidctest.NewMockIssuer(t)

	cfg := &config.Config{Issuer: m.Issuer(), ClientID: oidctest.ClientID, NonInteractive: true}
	var prompt bytes.Buffer
	src := &Source{
		Issuer: cfg.Issuer, ClientID: cfg.ClientID, Scope: "openid",
		GrantType:      GrantAuto,
		Env:            Environment{TTY: false, Display: false},
		NonInteractive: true,
		Prompt:         &prompt,
	}
	rnr := &runner.Runner{Cache: cache.New(t.TempDir()), Source: src, Config: cfg, Stderr: &prompt}

	_, err := rnr.Run(context.Background())
	if err == nil {
		t.Fatal("expected an immediate failure: no browser, and --non-interactive excludes device-code")
	}
	for _, want := range []string{"authorization_code", "browser: unavailable", "terminal: unattended (--non-interactive)"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want it to contain %q", err, want)
		}
	}
	if prompt.Len() != 0 {
		t.Fatalf("must never print a prompt before failing fast, got: %q", prompt.String())
	}
}

func TestIntegration_ExplicitDeviceCode_NonInteractive_FailsFast(t *testing.T) {
	m := oidctest.NewMockIssuer(t)

	cfg := &config.Config{Issuer: m.Issuer(), ClientID: oidctest.ClientID, NonInteractive: true}
	var prompt bytes.Buffer
	src := &Source{
		Issuer: cfg.Issuer, ClientID: cfg.ClientID, Scope: "openid",
		GrantType:      GrantDeviceCode,
		Env:            Environment{TTY: true, Display: true},
		NonInteractive: true,
		Prompt:         &prompt,
	}
	rnr := &runner.Runner{Cache: cache.New(t.TempDir()), Source: src, Config: cfg, Stderr: &prompt}

	_, err := rnr.Run(context.Background())
	if err == nil {
		t.Fatal("expected an explicit --grant-type=device-code request to fail under --non-interactive")
	}
	if !strings.Contains(err.Error(), "requires an attended terminal") {
		t.Fatalf("error = %v, want a reason specific to the explicit grant request", err)
	}
}

func TestIntegration_LoginMissingRefreshToken_WarnsLoudly(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.IncludeIDToken = true
	m.OmitRefreshToken = true

	var stderr bytes.Buffer
	cfg := &config.Config{}
	rnr := newIntegrationRunner(t, m, cfg, &stderr)

	res, err := rnr.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a token even without refresh_token")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("refresh_token")) {
		t.Fatalf("expected a loud stderr warning about the missing refresh_token, got: %q", stderr.String())
	}
}
