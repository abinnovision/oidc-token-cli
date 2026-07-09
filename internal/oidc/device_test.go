package oidc

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/abinnovision/oidc-token-cli/internal/oidctest"
)

func TestDeviceLogin_Success_PromptOnWriterOnly(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.IncludeIDToken = true
	m.PendingPolls = 1 // one authorization_pending, then success

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var prompt bytes.Buffer
	res, err := p.DeviceLogin(context.Background(), "openid offline_access", &prompt)
	if err != nil {
		t.Fatalf("DeviceLogin: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
	if res.IDToken == "" {
		t.Fatal("expected a non-empty (and verified) id_token")
	}
	if res.RefreshToken == "" {
		t.Fatal("expected a non-empty refresh_token")
	}
	if !strings.Contains(prompt.String(), "USER-CODE") {
		t.Fatalf("expected the user code to be written to the prompt writer, got: %q", prompt.String())
	}
}

func TestDeviceLogin_NotAdvertised_ClearError(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.NoDeviceEndpoint = true

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var prompt bytes.Buffer
	_, err = p.DeviceLogin(context.Background(), "openid", &prompt)
	if err == nil {
		t.Fatal("expected an error when the issuer does not advertise device_authorization_endpoint")
	}
	if !strings.Contains(err.Error(), "device_authorization_endpoint") {
		t.Fatalf("error should cite the missing capability, got: %v", err)
	}
	if prompt.Len() != 0 {
		t.Fatal("must not print any prompt when the grant is unavailable")
	}
}

func TestDeviceLogin_OmittedExpiresIn_BoundedByFallbackTimeout(t *testing.T) {
	orig := deviceLoginFallbackTimeout
	deviceLoginFallbackTimeout = 300 * time.Millisecond
	defer func() { deviceLoginFallbackTimeout = orig }()

	m := oidctest.NewMockIssuer(t)
	m.OmitDeviceExpiresIn = true
	m.PendingPolls = 1_000_000 // never actually completes within the test

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var prompt bytes.Buffer
	start := time.Now()
	_, err = p.DeviceLogin(context.Background(), "openid", &prompt)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error: the poll never succeeds and expires_in was omitted")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("DeviceLogin took %v to give up, want bounded by the fallback timeout (an issuer omitting expires_in must not poll forever)", elapsed)
	}
}

func TestDeviceLogin_ExplicitlyExcludedGrant_ClearError(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	// device_authorization_endpoint present, but grant_types_supported is
	// present AND excludes device-code: an explicit exclusion, not absence.
	m.GrantTypesSupported = []string{"authorization_code"}

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var prompt bytes.Buffer
	_, err = p.DeviceLogin(context.Background(), "openid", &prompt)
	if err == nil {
		t.Fatal("expected an error when grant_types_supported explicitly excludes device-code")
	}
}
