package runner

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/abinnovision/oidc-token-cli/internal/cache"
	"github.com/abinnovision/oidc-token-cli/internal/config"
	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// fakeSource is the injected TokenSource used to test the orchestration
// contract in isolation.
type fakeSource struct {
	refreshResult output.Result
	refreshErr    error
	refreshCalled bool

	loginResult output.Result
	loginErr    error
	loginCalled bool
}

func (f *fakeSource) Refresh(ctx context.Context, refreshToken string) (output.Result, error) {
	f.refreshCalled = true
	return f.refreshResult, f.refreshErr
}

func (f *fakeSource) Login(ctx context.Context) (output.Result, error) {
	f.loginCalled = true
	return f.loginResult, f.loginErr
}

func newRunner(t *testing.T, src TokenSource, cfg *config.Config, stderr *bytes.Buffer) *Runner {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{Issuer: "https://issuer.example", ClientID: "cid"}
	}
	return &Runner{
		Cache:  cache.New(t.TempDir()),
		Source: src,
		Config: cfg,
		Now:    func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) },
		Stderr: stderr,
	}
}

func TestRun_ValidCache_NoNetworkCalls(t *testing.T) {
	src := &fakeSource{}
	r := newRunner(t, src, nil, nil)
	now := r.Now()
	if err := r.Cache.Save(cache.Entry{
		Issuer: r.Config.Issuer, ClientID: r.Config.ClientID,
		AccessToken: "cached-token", Expiry: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.AccessToken != "cached-token" {
		t.Fatalf("AccessToken = %q, want cached-token", res.AccessToken)
	}
	if src.refreshCalled || src.loginCalled {
		t.Fatal("valid cache hit must not touch the network")
	}
}

func TestRun_ZeroExpiry_WithRefreshToken_RefreshesEagerly(t *testing.T) {
	src := &fakeSource{
		refreshResult: output.Result{AccessToken: "refreshed", RefreshToken: "rt-rotated"},
	}
	r := newRunner(t, src, nil, nil)
	if err := r.Cache.Save(cache.Entry{
		Issuer: r.Config.Issuer, ClientID: r.Config.ClientID,
		AccessToken: "stale-unknown-age", RefreshToken: "rt-old",
		// Expiry intentionally left zero: no expiry info from the issuer.
	}); err != nil {
		t.Fatal(err)
	}

	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.AccessToken != "refreshed" {
		t.Fatalf("AccessToken = %q, want refreshed: a zero-expiry cached token with a refresh_token must be refreshed eagerly, not served forever", res.AccessToken)
	}
	if !src.refreshCalled {
		t.Fatal("expected Refresh to be called for a zero-expiry entry that has a refresh_token")
	}
}

func TestRun_ZeroExpiry_NoRefreshToken_ServedIndefinitely(t *testing.T) {
	src := &fakeSource{}
	r := newRunner(t, src, nil, nil)
	if err := r.Cache.Save(cache.Entry{
		Issuer: r.Config.Issuer, ClientID: r.Config.ClientID,
		AccessToken: "only-token-we-have",
		// Expiry zero, no refresh_token: nothing to refresh with.
	}); err != nil {
		t.Fatal(err)
	}

	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.AccessToken != "only-token-we-have" {
		t.Fatalf("AccessToken = %q, want the cached token served as-is", res.AccessToken)
	}
	if src.refreshCalled || src.loginCalled {
		t.Fatal("a zero-expiry entry with no refresh_token must be served from cache, not trigger refresh/login (nothing to refresh with)")
	}
}

func TestRun_ExpiredCache_RefreshSucceeds_NoLogin(t *testing.T) {
	src := &fakeSource{
		refreshResult: output.Result{AccessToken: "refreshed", RefreshToken: "rt-rotated", Expiry: time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC)},
	}
	r := newRunner(t, src, nil, nil)
	now := r.Now()
	if err := r.Cache.Save(cache.Entry{
		Issuer: r.Config.Issuer, ClientID: r.Config.ClientID,
		AccessToken: "stale", RefreshToken: "rt-old", Expiry: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.AccessToken != "refreshed" {
		t.Fatalf("AccessToken = %q, want refreshed", res.AccessToken)
	}
	if !src.refreshCalled {
		t.Fatal("expected Refresh to be called for expired cache with a refresh token")
	}
	if src.loginCalled {
		t.Fatal("must not fall back to Login when Refresh succeeds")
	}

	// Rotated refresh token must be persisted.
	entry, ok, err := r.Cache.Load(r.Config.Issuer, r.Config.ClientID)
	if err != nil || !ok {
		t.Fatalf("Load after refresh: ok=%v err=%v", ok, err)
	}
	if entry.RefreshToken != "rt-rotated" {
		t.Fatalf("persisted RefreshToken = %q, want rotated value", entry.RefreshToken)
	}
}

func TestRun_RefreshFails_FallsBackToLogin(t *testing.T) {
	src := &fakeSource{
		refreshErr:  errors.New("token endpoint: invalid_grant"),
		loginResult: output.Result{AccessToken: "from-login", RefreshToken: "rt-new", Expiry: time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC)},
	}
	r := newRunner(t, src, nil, nil)
	now := r.Now()
	if err := r.Cache.Save(cache.Entry{
		Issuer: r.Config.Issuer, ClientID: r.Config.ClientID,
		AccessToken: "stale", RefreshToken: "rt-old", Expiry: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.AccessToken != "from-login" {
		t.Fatalf("AccessToken = %q, want from-login", res.AccessToken)
	}
	if !src.refreshCalled || !src.loginCalled {
		t.Fatalf("expected both Refresh and Login to be attempted: refresh=%v login=%v", src.refreshCalled, src.loginCalled)
	}
}

func TestRun_NonInteractive_DelegatesLoginDecisionToSource(t *testing.T) {
	// The Runner delegates the --non-interactive viability decision to the
	// TokenSource; a negotiation failure wraps as ErrLoginFailed.
	src := &fakeSource{loginErr: errors.New("authflow: no viable login method: ...")}
	cfg := &config.Config{Issuer: "https://issuer.example", ClientID: "cid", NonInteractive: true}
	r := newRunner(t, src, cfg, nil)

	_, err := r.Run(context.Background())
	if err == nil {
		t.Fatal("expected error under --non-interactive with no usable cache")
	}
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("error = %v, want wrapping ErrLoginFailed", err)
	}
	if !src.loginCalled {
		t.Fatal("expected Login to be called: the Runner delegates the --non-interactive decision to the TokenSource")
	}
}

func TestRun_NoCache_Interactive_LoginSucceeds(t *testing.T) {
	src := &fakeSource{
		loginResult: output.Result{AccessToken: "fresh", RefreshToken: "rt", Expiry: time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC)},
	}
	r := newRunner(t, src, nil, nil)

	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.AccessToken != "fresh" {
		t.Fatalf("AccessToken = %q, want fresh", res.AccessToken)
	}

	entry, ok, err := r.Cache.Load(r.Config.Issuer, r.Config.ClientID)
	if err != nil || !ok {
		t.Fatalf("Load after login: ok=%v err=%v", ok, err)
	}
	if entry.AccessToken != "fresh" || entry.RefreshToken != "rt" {
		t.Fatalf("cache not persisted correctly after login: %+v", entry)
	}
}

func TestRun_LoginMissingRefreshToken_WarnsOnStderr(t *testing.T) {
	src := &fakeSource{
		loginResult: output.Result{AccessToken: "fresh", Expiry: time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC)}, // no RefreshToken
	}
	var stderr bytes.Buffer
	r := newRunner(t, src, nil, &stderr)

	if _, err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(stderr.String(), "refresh_token") {
		t.Fatalf("expected a stderr warning about missing refresh_token, got: %q", stderr.String())
	}
}

func TestRun_CorruptCache_TreatedAsMiss_GoesToLogin(t *testing.T) {
	src := &fakeSource{
		loginResult: output.Result{AccessToken: "fresh-after-corrupt", RefreshToken: "rt"},
	}
	r := newRunner(t, src, nil, nil)

	// Simulate a corrupt cache file directly (bypassing Save's JSON encoding).
	dir := r.Cache.Dir
	if err := writeCorruptCacheFile(dir, r.Config.Issuer, r.Config.ClientID); err != nil {
		t.Fatal(err)
	}

	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.AccessToken != "fresh-after-corrupt" {
		t.Fatalf("AccessToken = %q, want login result (corrupt cache must be a miss)", res.AccessToken)
	}
	if !src.loginCalled {
		t.Fatal("expected Login to be called after a corrupt cache")
	}
}

func TestRun_LoginFails_ErrorWrapped(t *testing.T) {
	src := &fakeSource{loginErr: errors.New("authorization_pending timeout")}
	r := newRunner(t, src, nil, nil)

	_, err := r.Run(context.Background())
	if err == nil {
		t.Fatal("expected error when Login fails")
	}
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("error = %v, want wrapping ErrLoginFailed", err)
	}
}

func TestRun_Login_IDTokenInvalid_AccessTokenRequested_WarnsAndContinues(t *testing.T) {
	src := &fakeSource{
		loginResult: output.Result{
			AccessToken:  "at",
			RefreshToken: "rt",
			IDTokenError: errors.New("id_token verification failed: signature mismatch"),
		},
	}
	var stderr bytes.Buffer
	cfg := &config.Config{Issuer: "https://issuer.example", ClientID: "cid", TokenType: config.TokenTypeAccessToken}
	r := newRunner(t, src, cfg, &stderr)

	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run must not fail when only access_token was requested, got: %v", err)
	}
	if res.AccessToken != "at" {
		t.Fatalf("AccessToken = %q, want at", res.AccessToken)
	}
	if !strings.Contains(stderr.String(), "id_token") {
		t.Fatalf("expected a stderr warning mentioning id_token, got: %q", stderr.String())
	}
}

func TestRun_Login_IDTokenInvalid_IDTokenRequested_HardFails(t *testing.T) {
	src := &fakeSource{
		loginResult: output.Result{
			AccessToken:  "at",
			RefreshToken: "rt",
			IDTokenError: errors.New("id_token verification failed: signature mismatch"),
		},
	}
	cfg := &config.Config{Issuer: "https://issuer.example", ClientID: "cid", TokenType: config.TokenTypeIDToken}
	r := newRunner(t, src, cfg, nil)

	_, err := r.Run(context.Background())
	if err == nil {
		t.Fatal("expected Run to fail when --token-type=id_token was requested and the id_token failed verification")
	}
	if !errors.Is(err, ErrIDTokenInvalid) {
		t.Fatalf("error = %v, want wrapping ErrIDTokenInvalid", err)
	}
}

// lockCheckingSource's Login tries to acquire the same profile lock the
// runner's tryRefresh uses; if the runner still held it, this would time out.
type lockCheckingSource struct {
	cache            *cache.Cache
	issuer, clientID string
	loginResult      output.Result
	lockWasFree      chan bool
}

func (s *lockCheckingSource) Refresh(ctx context.Context, refreshToken string) (output.Result, error) {
	return output.Result{}, errors.New("unused in this test")
}

func (s *lockCheckingSource) Login(ctx context.Context) (output.Result, error) {
	lockCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	err := s.cache.WithLock(lockCtx, s.issuer, s.clientID, func() error {
		s.lockWasFree <- true
		return nil
	})
	if err != nil {
		s.lockWasFree <- false
	}
	return s.loginResult, nil
}

func TestRun_LockNotHeldDuringInteractiveLogin(t *testing.T) {
	dir := t.TempDir()
	c := cache.New(dir)
	cfg := &config.Config{Issuer: "https://issuer.example", ClientID: "cid"}

	lockWasFree := make(chan bool, 1)
	src := &lockCheckingSource{
		cache: c, issuer: cfg.Issuer, clientID: cfg.ClientID,
		loginResult: output.Result{AccessToken: "at", RefreshToken: "rt"},
		lockWasFree: lockWasFree,
	}
	r := &Runner{Cache: c, Source: src, Config: cfg, Now: time.Now}

	if _, err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	select {
	case free := <-lockWasFree:
		if !free {
			t.Fatal("Login could not acquire the profile lock — the runner must never hold it across interactive login (flock is scoped to read->refresh->write only)")
		}
	default:
		t.Fatal("lockCheckingSource.Login was never called")
	}
}

func writeCorruptCacheFile(dir, issuer, clientID string) error {
	c := cache.New(dir)
	// Use Save to create a well-formed file first (ensures dir exists with
	// correct perms), then overwrite its contents with garbage.
	if err := c.Save(cache.Entry{Issuer: issuer, ClientID: clientID}); err != nil {
		return err
	}
	return os.WriteFile(c.Path(issuer, clientID), []byte("{not valid json"), 0o600)
}
