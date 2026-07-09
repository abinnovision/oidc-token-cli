//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/abinnovision/oidc-token-cli/internal/oidc"
)

// TestE2E_Discovery proves oidc.Discover parses a real, spec-compliant
// discovery document — the actual field shapes dex produces, not what
// internal/oidctest's mock issuer assumes.
func TestE2E_Discovery(t *testing.T) {
	dex := StartDex(t)

	p, err := oidc.Discover(context.Background(), dex.IssuerURL, dex.ClientID)
	if err != nil {
		t.Fatalf("oidc.Discover: %v", err)
	}
	if !p.SupportsGrant("authorization_code") {
		t.Fatal("expected dex to advertise the authorization_code grant")
	}
	if got := p.AdvertisedGrants(); got == "" {
		t.Fatal("AdvertisedGrants returned empty")
	}
}
