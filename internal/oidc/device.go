package oidc

import (
	"context"
	"fmt"
	"io"
	"time"

	"golang.org/x/oauth2"

	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// deviceLoginFallbackTimeout bounds the device-code poll loop when the
// issuer's device-authorization response omits expires_in (non-compliant
// with RFC 8628 §3.2, but issuers do this). A var, not const, so tests can
// shrink it.
var deviceLoginFallbackTimeout = 15 * time.Minute

// DeviceLogin runs the RFC 8628 device-authorization grant: fetch a device
// code + user code, print the verification URL and code to prompt (stderr
// only — never stdout), then poll the token endpoint until the user
// completes the flow, the device code expires, or ctx is cancelled.
func (p *Provider) DeviceLogin(ctx context.Context, scope string, prompt io.Writer) (output.Result, error) {
	if !p.SupportsDeviceCode() {
		return output.Result{}, fmt.Errorf("oidc: issuer %s does not advertise device_authorization_endpoint; device-code grant unavailable (issuer advertises: %s)", p.Issuer, p.AdvertisedGrants())
	}
	if !p.SupportsGrant("urn:ietf:params:oauth:grant-type:device_code") {
		return output.Result{}, fmt.Errorf("oidc: issuer %s advertises grant_types_supported without device-code; device-code grant unavailable (issuer advertises: %s)", p.Issuer, p.AdvertisedGrants())
	}

	ctx = withHTTPClient(ctx)
	cfg := p.oauth2Config(scope)

	var opts []oauth2.AuthCodeOption
	if p.Audience != "" {
		opts = append(opts, oauth2.SetAuthURLParam("audience", p.Audience))
	}

	da, err := cfg.DeviceAuth(ctx, opts...)
	if err != nil {
		return output.Result{}, fmt.Errorf("oidc: device authorization request failed: %w", err)
	}

	verificationURI := da.VerificationURIComplete
	if verificationURI == "" {
		verificationURI = da.VerificationURI
	}
	fmt.Fprintf(prompt, "To sign in, visit:\n\n  %s\n\nand enter the code: %s\n\n", verificationURI, da.UserCode)

	// Fall back to our own bound when da.Expiry is zero and ctx has no
	// deadline, so this can never hang forever.
	if da.Expiry.IsZero() {
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, deviceLoginFallbackTimeout)
			defer cancel()
		}
	}

	tok, err := cfg.DeviceAccessToken(ctx, da, opts...)
	if err != nil {
		return output.Result{}, fmt.Errorf("oidc: device-code token exchange failed: %w", err)
	}

	return p.toResult(ctx, tok, "") // device-code doesn't use a nonce
}
