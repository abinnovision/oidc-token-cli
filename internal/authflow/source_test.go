package authflow

import (
	"bytes"
	"context"
	"errors"
	"testing"

	upstream "golang.org/x/oauth2"

	"github.com/abinnovision/oidc-token-cli/internal/oidc"
	"github.com/abinnovision/oidc-token-cli/internal/output"
)

func newTestSource(fp *fakeProvider, grantType GrantType, env Environment, nonInteractive bool, prompt *bytes.Buffer) *Source {
	return &Source{
		Issuer:         "https://issuer.example",
		ClientID:       "cid",
		Scope:          "openid offline_access",
		GrantType:      grantType,
		NonInteractive: nonInteractive,
		Env:            env,
		Prompt:         prompt,
		discoverFunc: func(ctx context.Context, issuer, clientID string) (grantSource, error) {
			return fp, nil
		},
	}
}

func TestSourceLogin_BothPossible_PrimarySucceeds_NoFallback(t *testing.T) {
	fp := &fakeProvider{
		supportsAuthcode: true, supportsDevice: true,
		loginResult: output.Result{AccessToken: "ok"},
	}
	var prompt bytes.Buffer
	s := newTestSource(fp, GrantAuto, Environment{TTY: true, Display: true}, false, &prompt)

	res, err := s.Login(context.Background())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.AccessToken != "ok" {
		t.Fatalf("AccessToken = %q, want ok", res.AccessToken)
	}
	if fp.authcodeCalls != 1 || fp.deviceCalls != 0 {
		t.Fatalf("authcodeCalls=%d deviceCalls=%d, want exactly one authcode attempt and no fallback", fp.authcodeCalls, fp.deviceCalls)
	}
}

func TestSourceLogin_PerClientRejection_FallsBackOnce(t *testing.T) {
	fp := &fakeProvider{
		supportsAuthcode: true, supportsDevice: true,
		authcodeErr: &upstream.RetrieveError{ErrorCode: "unauthorized_client"},
		loginResult: output.Result{AccessToken: "from-device"},
	}
	var prompt bytes.Buffer
	s := newTestSource(fp, GrantAuto, Environment{TTY: true, Display: true}, false, &prompt)

	res, err := s.Login(context.Background())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.AccessToken != "from-device" {
		t.Fatalf("AccessToken = %q, want from-device (fallback result)", res.AccessToken)
	}
	if fp.authcodeCalls != 1 || fp.deviceCalls != 1 {
		t.Fatalf("authcodeCalls=%d deviceCalls=%d, want exactly one of each (bounded fallback, no cycles)", fp.authcodeCalls, fp.deviceCalls)
	}
}

func TestSourceLogin_NonPerClientError_NoFallback(t *testing.T) {
	fp := &fakeProvider{
		supportsAuthcode: true, supportsDevice: true,
		authcodeErr: errors.New("network unreachable"), // not a RetrieveError/AuthorizationError
	}
	var prompt bytes.Buffer
	s := newTestSource(fp, GrantAuto, Environment{TTY: true, Display: true}, false, &prompt)

	_, err := s.Login(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if fp.deviceCalls != 0 {
		t.Fatalf("deviceCalls = %d, want 0: a non-per-client error must not trigger fallback", fp.deviceCalls)
	}
}

func TestSourceLogin_InvalidGrantAtTokenExchange_SurfacesDirectly_NoFallback(t *testing.T) {
	// invalid_grant at the token endpoint means an expired/replayed code or
	// PKCE mismatch, not "this client can't use this grant", so it must
	// surface directly instead of triggering fallback.
	fp := &fakeProvider{
		supportsAuthcode: true, supportsDevice: true,
		authcodeErr: &upstream.RetrieveError{ErrorCode: "invalid_grant"},
	}
	var prompt bytes.Buffer
	s := newTestSource(fp, GrantAuto, Environment{TTY: true, Display: true}, false, &prompt)

	_, err := s.Login(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if fp.deviceCalls != 0 {
		t.Fatalf("deviceCalls = %d, want 0: token-exchange invalid_grant must not trigger fallback", fp.deviceCalls)
	}
}

func TestSourceLogin_BothGrantsRejected_NoInfiniteCycle(t *testing.T) {
	fp := &fakeProvider{
		supportsAuthcode: true, supportsDevice: true,
		authcodeErr: &upstream.RetrieveError{ErrorCode: "unauthorized_client"},
		deviceErr:   &upstream.RetrieveError{ErrorCode: "unauthorized_client"},
	}
	var prompt bytes.Buffer
	s := newTestSource(fp, GrantAuto, Environment{TTY: true, Display: true}, false, &prompt)

	_, err := s.Login(context.Background())
	if err == nil {
		t.Fatal("expected an error when both grants are rejected")
	}
	if fp.authcodeCalls != 1 || fp.deviceCalls != 1 {
		t.Fatalf("authcodeCalls=%d deviceCalls=%d, want exactly one attempt each, then stop (no authcode->device->authcode cycle)", fp.authcodeCalls, fp.deviceCalls)
	}
}

func TestSourceLogin_AuthorizationEndpointRejection_TriggersFallback(t *testing.T) {
	fp := &fakeProvider{
		supportsAuthcode: true, supportsDevice: true,
		authcodeErr: &oidc.AuthorizationError{Code: "unauthorized_client"},
		loginResult: output.Result{AccessToken: "from-device"},
	}
	var prompt bytes.Buffer
	s := newTestSource(fp, GrantAuto, Environment{TTY: true, Display: true}, false, &prompt)

	res, err := s.Login(context.Background())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.AccessToken != "from-device" {
		t.Fatalf("AccessToken = %q, want fallback result", res.AccessToken)
	}
}

func TestSourceLogin_NonInteractive_NoBrowser_NeverCallsLogin(t *testing.T) {
	// Terminal unattended AND no browser: no viable grant at all.
	fp := &fakeProvider{supportsAuthcode: true, supportsDevice: true}
	var prompt bytes.Buffer
	s := newTestSource(fp, GrantAuto, Environment{TTY: true, Display: false}, true, &prompt)

	_, err := s.Login(context.Background())
	if err == nil {
		t.Fatal("expected an error under --non-interactive with no browser available")
	}
	if !errors.Is(err, ErrInteractionUnavailable) {
		t.Fatalf("err = %v, want wrapping ErrInteractionUnavailable", err)
	}
	if fp.authcodeCalls != 0 || fp.deviceCalls != 0 {
		t.Fatalf("authcodeCalls=%d deviceCalls=%d, want 0/0", fp.authcodeCalls, fp.deviceCalls)
	}
	if prompt.Len() != 0 {
		t.Fatalf("prompt = %q, want empty: must never print anything before failing fast", prompt.String())
	}
}

func TestSourceLogin_NonInteractive_BrowserAvailable_AttemptsAuthcode(t *testing.T) {
	// --non-interactive means "terminal unattended", not "never log in":
	// authcode is still attempted when a browser is available.
	fp := &fakeProvider{
		supportsAuthcode: true, supportsDevice: true,
		loginResult: output.Result{AccessToken: "from-authcode"},
	}
	var prompt bytes.Buffer
	s := newTestSource(fp, GrantAuto, Environment{TTY: false, Display: true}, true, &prompt)

	res, err := s.Login(context.Background())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.AccessToken != "from-authcode" {
		t.Fatalf("AccessToken = %q, want from-authcode", res.AccessToken)
	}
	if fp.authcodeCalls != 1 || fp.deviceCalls != 0 {
		t.Fatalf("authcodeCalls=%d deviceCalls=%d, want exactly one authcode attempt and no device-code fallback under --non-interactive", fp.authcodeCalls, fp.deviceCalls)
	}
}

func TestSourceLogin_AuthCodeHint_AttendedTerminal_Printed(t *testing.T) {
	fp := &fakeProvider{supportsAuthcode: true, loginResult: output.Result{AccessToken: "ok"}}
	var prompt bytes.Buffer
	s := newTestSource(fp, GrantAuthCode, Environment{TTY: true, Display: true}, false, &prompt)

	if _, err := s.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !fp.lastHintNonNil {
		t.Fatal("expected a non-nil hint writer when the terminal is attended")
	}
	if fp.lastHintWrite == "" {
		t.Fatal("expected the authcode flow's hint text to reach the prompt writer")
	}
}

func TestSourceLogin_AuthCodeHint_UnattendedTerminal_Suppressed(t *testing.T) {
	// frpc-exec shape: no TTY, browser available. The optional "visit this
	// URL" hint must not be printed — nobody's reading frpc's captured
	// stderr — while the flow itself still runs (browser opened directly).
	fp := &fakeProvider{supportsAuthcode: true, loginResult: output.Result{AccessToken: "ok"}}
	var prompt bytes.Buffer
	s := newTestSource(fp, GrantAuthCode, Environment{TTY: false, Display: true}, false, &prompt)

	if _, err := s.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if fp.lastHintNonNil {
		t.Fatal("expected a nil hint writer when the terminal is unattended")
	}
}

func TestSourceRefresh_DelegatesToProvider(t *testing.T) {
	fp := &fakeProvider{loginResult: output.Result{AccessToken: "refreshed"}}
	var prompt bytes.Buffer
	s := newTestSource(fp, GrantAuto, Environment{}, false, &prompt)

	res, err := s.Refresh(context.Background(), "some-refresh-token")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if res.AccessToken != "refreshed" {
		t.Fatalf("AccessToken = %q, want refreshed", res.AccessToken)
	}
}
