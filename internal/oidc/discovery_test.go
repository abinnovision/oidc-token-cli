package oidc

import (
	"context"
	"testing"

	"github.com/abinnovision/oidc-token-cli/internal/oidctest"
)

func TestDiscover_ResolvesEndpointsAndCapabilities(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.GrantTypesSupported = []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code"}

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !p.SupportsDeviceCode() {
		t.Fatal("expected device_authorization_endpoint to be resolved from discovery")
	}
	if !p.SupportsGrant("urn:ietf:params:oauth:grant-type:device_code") {
		t.Fatal("expected device-code grant to be reported as supported")
	}
	if p.SupportsGrant("some-unlisted-grant") {
		t.Fatal("expected an unlisted grant to be reported as unsupported when grant_types_supported is present")
	}
}

func TestDiscover_AbsentGrantTypesSupported_DoesNotForbidDeviceCode(t *testing.T) {
	// grant_types_supported is OPTIONAL (OIDC Discovery §3); its absence
	// must never be read as "device-code is forbidden" — only
	// device_authorization_endpoint presence/absence decides that.
	m := oidctest.NewMockIssuer(t)
	// grantTypesSupported left nil: field omitted entirely from the doc.

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !p.SupportsDeviceCode() {
		t.Fatal("device_authorization_endpoint is present; device-code must be considered possible")
	}
	if !p.SupportsGrant("urn:ietf:params:oauth:grant-type:device_code") {
		t.Fatal("absent grant_types_supported must not forbid any grant")
	}
}

func TestDiscover_NoDeviceEndpoint_DeviceCodeUnsupported(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.NoDeviceEndpoint = true

	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if p.SupportsDeviceCode() {
		t.Fatal("expected SupportsDeviceCode()=false when discovery omits device_authorization_endpoint")
	}
}

func TestDiscover_IssuerMismatch_HardFailure(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.IssuerOverride = "https://not-the-real-issuer.example"

	_, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err == nil {
		t.Fatal("expected a hard failure when the discovery document's issuer field doesn't match the configured issuer URL")
	}
}

func TestValidateIssuerURL_RejectsHTTPNonLoopback(t *testing.T) {
	err := validateIssuerURL("http://issuer.example")
	if err == nil {
		t.Fatal("expected http:// to be rejected for a non-loopback host")
	}
}

func TestValidateIssuerURL_AllowsHTTPSAlways(t *testing.T) {
	if err := validateIssuerURL("https://issuer.example"); err != nil {
		t.Fatalf("https:// must always be allowed: %v", err)
	}
}

func TestValidateIssuerURL_AllowsLoopbackHTTP(t *testing.T) {
	if err := validateIssuerURL("http://127.0.0.1:12345"); err != nil {
		t.Fatalf("http://127.0.0.1 must be allowed for test issuers: %v", err)
	}
	if err := validateIssuerURL("http://[::1]:12345"); err != nil {
		t.Fatalf("http://[::1] must be allowed for test issuers: %v", err)
	}
}

func TestValidateIssuerURL_RejectsInvalidURL(t *testing.T) {
	if err := validateIssuerURL("://not a url"); err == nil {
		t.Fatal("expected an error for an unparseable issuer URL")
	}
}

func TestCodeChallengeMethod_AbsentDefaultsToS256(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	method, err := p.codeChallengeMethod()
	if err != nil {
		t.Fatalf("codeChallengeMethod: %v", err)
	}
	if method != "S256" {
		t.Fatalf("method = %q, want S256 when the field is absent", method)
	}
}

func TestCodeChallengeMethod_PresentWithoutS256_Refuses(t *testing.T) {
	m := oidctest.NewMockIssuer(t)
	m.CodeChallengeMethodsSupported = []string{"plain"}
	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, err := p.codeChallengeMethod(); err == nil {
		t.Fatal("expected refusal to downgrade to plain when S256 is absent from an explicit list")
	}
}
