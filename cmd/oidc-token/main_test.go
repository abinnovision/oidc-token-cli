package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/abinnovision/oidc-token-cli/internal/cache"
	"github.com/abinnovision/oidc-token-cli/internal/config"
	"github.com/abinnovision/oidc-token-cli/internal/output"
	"github.com/abinnovision/oidc-token-cli/internal/runner"
)

// fakeSource is the network-facing double injected in place of newRealSource
// for these golden tests of run()'s stdout/exit contract.
type fakeSource struct {
	loginResult output.Result
	loginErr    error
}

func (f fakeSource) Refresh(ctx context.Context, refreshToken string) (output.Result, error) {
	return output.Result{}, errors.New("unused in these tests")
}

func (f fakeSource) Login(ctx context.Context) (output.Result, error) {
	return f.loginResult, f.loginErr
}

// fakeTokenExchange is the network-facing double injected in place of
// newRealTokenExchangeSource.
type fakeTokenExchange struct {
	result output.Result
	err    error
}

func (f fakeTokenExchange) TokenExchange(ctx context.Context, subjectToken, subjectTokenType, requestedTokenType string, resources []string) (output.Result, error) {
	return f.result, f.err
}

// failTokenExchange returns a newTokenExchangeFunc that fails the test if
// invoked, for tests exercising grants other than token-exchange.
func failTokenExchange(t *testing.T) newTokenExchangeFunc {
	return func(cfg *config.Config) tokenExchanger {
		t.Fatal("must not construct a tokenExchanger")
		return nil
	}
}

func TestRun_Success_BareTokenExactBytes_EmptyStderr_ExitZero(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"--issuer=https://issuer.example", "--client-id=cid",
		"--cache-dir=" + filepath.Join(dir, "cache"), "--token-store=file",
	}, &stdout, &stderr, func(cfg *config.Config) runner.TokenSource {
		return fakeSource{loginResult: output.Result{AccessToken: "the-access-token", RefreshToken: "rt"}}
	}, failTokenExchange(t))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if got := stdout.String(); got != "the-access-token" {
		t.Fatalf("stdout = %q, want exact token bytes with no trailing newline", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty on success", stderr.String())
	}
}

func TestRun_Success_All_ValidJSON(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--all",
		"--cache-dir=" + filepath.Join(dir, "cache"), "--token-store=file",
	}, &stdout, &stderr, func(cfg *config.Config) runner.TokenSource {
		return fakeSource{loginResult: output.Result{AccessToken: "at", IDToken: "it", RefreshToken: "rt"}}
	}, failTokenExchange(t))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("--all stdout is not valid JSON: %v, raw: %s", err, stdout.String())
	}
}

func TestRun_LoginFailure_ExitNonZero_EmptyStdout_NonEmptyStderr(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"--issuer=https://issuer.example", "--client-id=cid",
		"--cache-dir=" + filepath.Join(dir, "cache"), "--token-store=file",
	}, &stdout, &stderr, func(cfg *config.Config) runner.TokenSource {
		return fakeSource{loginErr: errors.New("mock issuer rejected login")}
	}, failTokenExchange(t))

	if code == 0 {
		t.Fatal("exit code = 0, want non-zero on failure")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want byte-for-byte empty on failure", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr must be non-empty on failure")
	}
}

func TestRun_NoViableGrant_ExitNonZero_EmptyStdout(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	diagnostic := "authflow: no viable login method: IdP offers [authorization_code]; browser: unavailable (no $DISPLAY/$WAYLAND_DISPLAY); terminal: unattended (--non-interactive)"
	code := run([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--non-interactive",
		"--cache-dir=" + filepath.Join(dir, "cache"), "--token-store=file",
	}, &stdout, &stderr, func(cfg *config.Config) runner.TokenSource {
		return fakeSource{loginErr: errors.New(diagnostic)}
	}, failTokenExchange(t))

	if code == 0 {
		t.Fatal("exit code = 0, want non-zero when no grant is viable")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want byte-for-byte empty on failure", stdout.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("no viable login method")) {
		t.Fatalf("stderr = %q, want the negotiation diagnostic", stderr.String())
	}
}

func TestRun_MissingRequiredFlags_ExitNonZero_EmptyStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(nil, &stdout, &stderr, func(cfg *config.Config) runner.TokenSource {
		t.Fatal("must not construct a TokenSource when config validation fails")
		return nil
	}, failTokenExchange(t))

	if code == 0 {
		t.Fatal("exit code = 0, want non-zero when --issuer/--client-id are missing")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Fatal("stderr must explain the missing flags")
	}
}

func TestRun_Help_ExitZero_EmptyStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"--help"}, &stdout, &stderr, func(cfg *config.Config) runner.TokenSource {
		t.Fatal("must not construct a TokenSource for --help")
		return nil
	}, failTokenExchange(t))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 for --help", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty (usage goes to stderr)", stdout.String())
	}
}

func TestRun_RequestedTokenTypeMissing_ExitNonZero_EmptyStdout(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--token-type=id_token",
		"--cache-dir=" + filepath.Join(dir, "cache"), "--token-store=file",
	}, &stdout, &stderr, func(cfg *config.Config) runner.TokenSource {
		return fakeSource{loginResult: output.Result{AccessToken: "at-only"}}
	}, failTokenExchange(t))

	if code == 0 {
		t.Fatal("exit code = 0, want non-zero when the requested token type is absent")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty on failure", stdout.String())
	}
}

func TestBuildStore_File(t *testing.T) {
	var stderr bytes.Buffer
	cfg := &config.Config{TokenStore: cache.BackendFile, CacheDir: t.TempDir()}
	store, err := buildStore(context.Background(), cfg, &stderr)
	if err != nil {
		t.Fatalf("buildStore: %v", err)
	}
	if _, ok := store.(*cache.Cache); !ok {
		t.Fatalf("store = %T, want *cache.Cache", store)
	}
}

func TestBuildStore_Auto(t *testing.T) {
	var stderr bytes.Buffer
	cfg := &config.Config{TokenStore: cache.BackendAuto, CacheDir: t.TempDir()}
	store, err := buildStore(context.Background(), cfg, &stderr)
	if err != nil {
		t.Fatalf("buildStore: %v", err)
	}
	chain, ok := store.(*cache.ChainStore)
	if !ok {
		t.Fatalf("store = %T, want *cache.ChainStore", store)
	}
	if len(chain.Backends) != 2 {
		t.Fatalf("len(Backends) = %d, want 2 (keychain, file)", len(chain.Backends))
	}
}

func TestRun_Logout_ClearsCacheEntry_ExitZero(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	var stdout, stderr bytes.Buffer

	// Bootstrap a cached entry via a normal login.
	code := run([]string{
		"--issuer=https://issuer.example", "--client-id=cid",
		"--token-store=file", "--cache-dir=" + cacheDir,
	}, &stdout, &stderr, func(cfg *config.Config) runner.TokenSource {
		return fakeSource{loginResult: output.Result{AccessToken: "at", RefreshToken: "rt"}}
	}, failTokenExchange(t))
	if code != 0 {
		t.Fatalf("bootstrap exit code = %d (stderr: %s)", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"--issuer=https://issuer.example", "--client-id=cid",
		"--token-store=file", "--cache-dir=" + cacheDir, "--logout",
	}, &stdout, &stderr, func(cfg *config.Config) runner.TokenSource {
		t.Fatal("--logout must not construct a TokenSource")
		return nil
	}, failTokenExchange(t))
	if code != 0 {
		t.Fatalf("logout exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty on logout", stdout.String())
	}

	// A subsequent run must miss the cache and need to log in again.
	stdout.Reset()
	stderr.Reset()
	loginCalled := false
	code = run([]string{
		"--issuer=https://issuer.example", "--client-id=cid",
		"--token-store=file", "--cache-dir=" + cacheDir,
	}, &stdout, &stderr, func(cfg *config.Config) runner.TokenSource {
		loginCalled = true
		return fakeSource{loginResult: output.Result{AccessToken: "at-2", RefreshToken: "rt-2"}}
	}, failTokenExchange(t))
	if code != 0 {
		t.Fatalf("post-logout exit code = %d (stderr: %s)", code, stderr.String())
	}
	if !loginCalled {
		t.Fatal("expected a fresh login after --logout cleared the cache")
	}
}

// TestHelpSubprocess builds the real binary and runs it as an actual OS
// subprocess, verifying the `oidc-token --help` contract end to end.
func TestHelpSubprocess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess build in -short mode")
	}
	bin := filepath.Join(t.TempDir(), "oidc-token")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	cmd := exec.Command(bin, "--help")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		t.Fatalf("oidc-token --help exited with error: %v (stderr: %s)", err, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRun_TokenExchange_BypassesCacheAndStore(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	newSourceCalled := false
	newSource := func(cfg *config.Config) runner.TokenSource {
		newSourceCalled = true
		t.Fatal("must not construct a runner.TokenSource for --grant-type=token-exchange")
		return nil
	}
	newTokenExchange := func(cfg *config.Config) tokenExchanger {
		return fakeTokenExchange{result: output.Result{AccessToken: "exchanged-token"}}
	}

	code := run([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
		"--subject-token=sub-tok",
		// A cache dir under a path that doesn't exist: if token-exchange
		// ever touched the store, buildStore/cache writes would fail loudly.
		"--cache-dir=" + filepath.Join(dir, "does-not-exist", "cache"), "--token-store=file",
	}, &stdout, &stderr, newSource, newTokenExchange)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if got := stdout.String(); got != "exchanged-token" {
		t.Fatalf("stdout = %q, want exact token bytes", got)
	}
	if newSourceCalled {
		t.Fatal("must not have called newSource for --grant-type=token-exchange")
	}
}

func TestRun_TokenExchange_All_ValidJSON(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	newTokenExchange := func(cfg *config.Config) tokenExchanger {
		return fakeTokenExchange{result: output.Result{AccessToken: "at", IssuedTokenType: "urn:ietf:params:oauth:token-type:jwt"}}
	}

	code := run([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
		"--subject-token=sub-tok", "--all",
		"--cache-dir=" + filepath.Join(dir, "cache"), "--token-store=file",
	}, &stdout, &stderr, func(cfg *config.Config) runner.TokenSource {
		t.Fatal("must not construct a runner.TokenSource for --grant-type=token-exchange")
		return nil
	}, newTokenExchange)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("--all stdout is not valid JSON: %v, raw: %s", err, stdout.String())
	}
	if doc["issued_token_type"] != "urn:ietf:params:oauth:token-type:jwt" {
		t.Fatalf("issued_token_type = %v, want the exchanged value", doc["issued_token_type"])
	}
}

func TestRun_TokenExchange_Failure_ExitNonZero_EmptyStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer

	newTokenExchange := func(cfg *config.Config) tokenExchanger {
		return fakeTokenExchange{err: errors.New("issuer rejected subject_token")}
	}

	code := run([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
		"--subject-token=sub-tok",
	}, &stdout, &stderr, func(cfg *config.Config) runner.TokenSource {
		t.Fatal("must not construct a runner.TokenSource for --grant-type=token-exchange")
		return nil
	}, newTokenExchange)

	if code == 0 {
		t.Fatal("exit code = 0, want non-zero on token-exchange failure")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty on failure", stdout.String())
	}
}
