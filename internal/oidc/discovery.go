package oidc

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	upstream "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// discoveryClaims captures discovery-document fields go-oidc's Provider
// doesn't expose. Every field is OIDC Discovery §3 OPTIONAL — absence must
// be treated as soft, never as "this grant is forbidden".
type discoveryClaims struct {
	DeviceAuthorizationEndpoint   string   `json:"device_authorization_endpoint"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	ScopesSupported               []string `json:"scopes_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

// Provider wraps a single issuer's runtime-discovered capabilities and
// endpoints.
type Provider struct {
	Issuer   string
	ClientID string
	Audience string

	upstream *upstream.Provider
	verifier *upstream.IDTokenVerifier
	claims   discoveryClaims

	clientAuth clientAuth
}

// Discover fetches and validates issuer's discovery document. The issuer
// URL must be HTTPS, except loopback (127.0.0.1/::1) for test mock issuers.
func Discover(ctx context.Context, issuer, clientID string) (*Provider, error) {
	if err := validateIssuerURL(issuer); err != nil {
		return nil, err
	}

	p, err := upstream.NewProvider(withHTTPClient(ctx), issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery failed for issuer %s: %w", issuer, err)
	}

	var claims discoveryClaims
	if err := p.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: parse discovery document for issuer %s: %w", issuer, err)
	}

	// VerifierContext binds the HTTP client for every future jwks fetch, not
	// just this one; its context's cancellation is ignored, so a bare
	// client-carrying background context is safe to reuse for its lifetime.
	verifier := p.VerifierContext(withHTTPClient(context.Background()), &upstream.Config{ClientID: clientID})

	return &Provider{
		Issuer:   issuer,
		ClientID: clientID,
		upstream: p,
		verifier: verifier,
		claims:   claims,
	}, nil
}

// validateIssuerURL enforces HTTPS except for loopback IP literals used by
// tests.
func validateIssuerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("oidc: invalid issuer URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		switch u.Hostname() {
		case "127.0.0.1", "::1":
			return nil
		default:
			return fmt.Errorf("oidc: issuer %q must use https:// (http:// is only permitted for loopback 127.0.0.1/[::1] test issuers)", raw)
		}
	default:
		return fmt.Errorf("oidc: issuer %q must use https:// (unsupported scheme %q)", raw, u.Scheme)
	}
}

// SetAudience sets the aud value requested via --audience.
func (p *Provider) SetAudience(audience string) {
	p.Audience = audience
}

// SupportsDeviceCode reports whether the issuer advertises a device
// authorization endpoint. grant_types_supported absence must not be read as
// forbidding device-code; only its explicit presence-and-exclusion does
// (see SupportsGrant).
func (p *Provider) SupportsDeviceCode() bool {
	return p.claims.DeviceAuthorizationEndpoint != ""
}

// SupportsGrant reports whether grant is forbidden by an explicit,
// present grant_types_supported list. If the field is absent, every grant
// is treated as possible (subject to the stronger endpoint-presence
// signals used elsewhere, e.g. SupportsDeviceCode).
func (p *Provider) SupportsGrant(grant string) bool {
	if len(p.claims.GrantTypesSupported) == 0 {
		return true
	}
	for _, g := range p.claims.GrantTypesSupported {
		if g == grant {
			return true
		}
	}
	return false
}

// AdvertisedGrants describes, for error messages, which grants the issuer
// appears to support: the explicit list if present, otherwise
// authorization_code plus device-code if its endpoint is advertised.
func (p *Provider) AdvertisedGrants() string {
	if len(p.claims.GrantTypesSupported) > 0 {
		return strings.Join(p.claims.GrantTypesSupported, ", ")
	}
	grants := []string{"authorization_code"}
	if p.claims.DeviceAuthorizationEndpoint != "" {
		grants = append(grants, "urn:ietf:params:oauth:grant-type:device_code")
	}
	return strings.Join(grants, ", ")
}

// codeChallengeMethod returns the PKCE code_challenge_method to use: S256 if
// supported or unspecified; refuses rather than downgrade to plain.
func (p *Provider) codeChallengeMethod() (string, error) {
	if len(p.claims.CodeChallengeMethodsSupported) == 0 {
		return "S256", nil
	}
	for _, m := range p.claims.CodeChallengeMethodsSupported {
		if m == "S256" {
			return "S256", nil
		}
	}
	return "", fmt.Errorf("oidc: issuer %s advertises code_challenge_methods_supported without S256; refusing to downgrade to plain", p.Issuer)
}

// oauth2Config builds an *oauth2.Config for scope, wiring in every endpoint
// discovery resolved.
func (p *Provider) oauth2Config(scope string) *oauth2.Config {
	ep := p.upstream.Endpoint()
	ep.DeviceAuthURL = p.claims.DeviceAuthorizationEndpoint
	cfg := &oauth2.Config{
		ClientID: p.ClientID,
		Endpoint: ep,
		Scopes:   strings.Fields(scope),
	}
	p.applyClientAuth(cfg)
	return cfg
}
