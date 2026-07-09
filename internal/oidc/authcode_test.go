package oidc

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abinnovision/oidc-token-cli/internal/oidctest"
)

// simulateBrowser parses the authorization URL for redirect_uri, state, and
// nonce, then asynchronously "navigates" to the redirect_uri with the given
// code. overrideState, if non-empty, is sent instead of the real state (to
// test CSRF rejection); errCode, if non-empty, sends an OAuth2 error
// instead of a code.
func simulateBrowser(t *testing.T, m *oidctest.MockIssuer, authURL, code, overrideState, errCode string) func(string) error {
	t.Helper()
	return func(rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			t.Errorf("openBrowser: parse authURL: %v", err)
			return nil
		}
		redirect := u.Query().Get("redirect_uri")
		state := u.Query().Get("state")
		if overrideState != "" {
			state = overrideState
		}
		m.NonceForAuthCode = u.Query().Get("nonce")
		go func() {
			cbURL, _ := url.Parse(redirect)
			q := cbURL.Query()
			q.Set("state", state)
			if errCode != "" {
				q.Set("error", errCode)
				q.Set("error_description", "mock rejection")
			} else {
				q.Set("code", code)
			}
			cbURL.RawQuery = q.Encode()
			resp, err := http.Get(cbURL.String())
			if err != nil {
				return
			}
			_ = resp.Body.Close()
		}()
		return nil
	}
}

func TestAuthCodeLogin_Success(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.IncludeIDToken = true

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var prompt bytes.Buffer
	captured := make(chan string, 1)
	openBrowser := func(u string) error {
		captured <- u
		return simulateBrowser(t, m, u, oidctest.MockAuthCode, "", "")(u)
	}

	res, err := p.AuthCodeLogin(context.Background(), "openid offline_access", 0, openBrowser, &prompt, &prompt)
	if err != nil {
		t.Fatalf("AuthCodeLogin: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
	if res.IDToken == "" {
		t.Fatal("expected a non-empty (and verified) id_token")
	}
	select {
	case <-captured:
	default:
		t.Fatal("expected openBrowser to be invoked with the authorization URL")
	}
}

func TestAuthCodeLogin_NilHint_SuppressesURLText_PromptStillGetsWarnings(t *testing.T) {
	m := oidctest.NewMockIssuer(t)

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var prompt bytes.Buffer
	openBrowserErr := errors.New("no display")
	openBrowser := func(string) error { return openBrowserErr }

	_, _ = p.AuthCodeLogin(ctx, "openid", 0, openBrowser, &prompt, nil)

	if !strings.Contains(prompt.String(), "could not open a browser") {
		t.Fatalf("prompt = %q, want the browser-open-failure warning even with a nil hint", prompt.String())
	}
	if strings.Contains(prompt.String(), "To sign in, visit") {
		t.Fatalf("prompt = %q, want no URL hint text when hint is nil", prompt.String())
	}
}

func TestAuthCodeLogin_WrongStateAlone_NeverCompletes_TimesOut(t *testing.T) {
	// A stray/forged wrong-state request must not end the flow; it should
	// keep waiting until ctx bounds it, not return early.
	m := oidctest.NewMockIssuer(t)

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	var prompt bytes.Buffer
	openBrowser := func(u string) error {
		return simulateBrowser(t, m, u, oidctest.MockAuthCode, "wrong-state", "")(u)
	}

	start := time.Now()
	_, err = p.AuthCodeLogin(ctx, "openid", 0, openBrowser, &prompt, &prompt)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error: a wrong-state request alone must never complete the flow")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("AuthCodeLogin took %v to give up, want bounded by ctx", elapsed)
	}
}

func TestAuthCodeLogin_AuthorizationEndpointRejection_PreLogin(t *testing.T) {
	m := oidctest.NewMockIssuer(t)

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var prompt bytes.Buffer
	openBrowser := func(u string) error {
		return simulateBrowser(t, m, u, "", "", "unauthorized_client")(u)
	}

	_, err = p.AuthCodeLogin(context.Background(), "openid", 0, openBrowser, &prompt, &prompt)
	if err == nil {
		t.Fatal("expected an error when the authorization endpoint rejects the client before login")
	}
	if !strings.Contains(err.Error(), "unauthorized_client") {
		t.Fatalf("error should surface the authorization-endpoint error code, got: %v", err)
	}
}

func TestAuthCodeLogin_Timeout_AbortsCleanly(t *testing.T) {
	m := oidctest.NewMockIssuer(t)

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var prompt bytes.Buffer
	_, err = p.AuthCodeLogin(ctx, "openid", 0, nil, &prompt, &prompt)
	if err == nil {
		t.Fatal("expected a timeout error when nobody completes the callback")
	}
}

func TestAuthCodeLogin_EphemeralPort_NonZero(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var gotPort string
	openBrowser := func(u string) error {
		parsed, _ := url.Parse(u)
		redirect, _ := url.Parse(parsed.Query().Get("redirect_uri"))
		gotPort = redirect.Port()
		return simulateBrowser(t, m, u, oidctest.MockAuthCode, "", "")(u)
	}

	var prompt bytes.Buffer
	if _, err := p.AuthCodeLogin(context.Background(), "openid", 0, openBrowser, &prompt, &prompt); err != nil {
		t.Fatalf("AuthCodeLogin: %v", err)
	}
	if gotPort == "" || gotPort == "0" {
		t.Fatalf("expected a non-zero ephemeral port, got %q", gotPort)
	}
}

func TestAuthCodeLogin_FixedPort_UsesExactPort(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	var gotPort string
	openBrowser := func(u string) error {
		parsed, _ := url.Parse(u)
		redirect, _ := url.Parse(parsed.Query().Get("redirect_uri"))
		gotPort = redirect.Port()
		return simulateBrowser(t, m, u, oidctest.MockAuthCode, "", "")(u)
	}

	var prompt bytes.Buffer
	if _, err := p.AuthCodeLogin(context.Background(), "openid", fixedPort, openBrowser, &prompt, &prompt); err != nil {
		t.Fatalf("AuthCodeLogin: %v", err)
	}
	if gotPort != strconv.Itoa(fixedPort) {
		t.Fatalf("redirect_uri port = %q, want fixed port %d", gotPort, fixedPort)
	}
}

func TestAuthCodeLogin_NotSupported_ClearError(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.GrantTypesSupported = []string{"urn:ietf:params:oauth:grant-type:device_code"}

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var prompt bytes.Buffer
	_, err = p.AuthCodeLogin(context.Background(), "openid", 0, nil, &prompt, &prompt)
	if err == nil {
		t.Fatal("expected an error when authorization_code is explicitly excluded")
	}
}

func TestAuthCodeLogin_PlainOnlyPKCE_Refuses(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.CodeChallengeMethodsSupported = []string{"plain"}

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var prompt bytes.Buffer
	_, err = p.AuthCodeLogin(context.Background(), "openid", 0, nil, &prompt, &prompt)
	if err == nil {
		t.Fatal("expected a refusal when the issuer only advertises plain PKCE")
	}
}

func TestAuthCodeLogin_NonceMismatch_RecordsIDTokenError_NotHardFailure(t *testing.T) {
	// AuthCodeLogin itself must not error on a nonce mismatch (that's the
	// runner's call); it records IDTokenError and leaves IDToken empty.
	m := oidctest.NewMockIssuer(t)
	m.IncludeIDToken = true

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var prompt bytes.Buffer
	openBrowser := func(u string) error {
		fn := simulateBrowser(t, m, u, oidctest.MockAuthCode, "", "")(u)
		// Overwrite the nonce so the mock signs a mismatching id_token.
		m.NonceForAuthCode = "a-completely-different-nonce"
		return fn
	}

	res, err := p.AuthCodeLogin(context.Background(), "openid", 0, openBrowser, &prompt, &prompt)
	if err != nil {
		t.Fatalf("AuthCodeLogin must not hard-fail on nonce mismatch, got: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected access_token to still be returned")
	}
	if res.IDToken != "" {
		t.Fatalf("expected IDToken to be empty after a nonce mismatch, got %q", res.IDToken)
	}
	if res.IDTokenError == nil {
		t.Fatal("expected IDTokenError to be set")
	}
	if !strings.Contains(res.IDTokenError.Error(), "nonce") {
		t.Fatalf("IDTokenError should mention nonce, got: %v", res.IDTokenError)
	}
}
