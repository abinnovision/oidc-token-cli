package oidc

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"time"

	"golang.org/x/oauth2"

	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// deviceLoginFallbackTimeout bounds the device-code poll loop when the
// issuer's device-authorization response omits expires_in (non-compliant
// with RFC 8628 §3.2, but issuers do this). A var, not const, so tests can
// shrink it.
var deviceLoginFallbackTimeout = 15 * time.Minute

// maxDeviceAssertionLifetime caps how long a private_key_jwt assertion
// minted for the device-code flow is allowed to live, even if the device
// code itself is valid longer.
const maxDeviceAssertionLifetime = 15 * time.Minute

// deviceAssertionLifetime sizes a private_key_jwt assertion's exp off the
// device code's own expiry, so it survives DeviceAccessToken's internal
// poll loop; it falls back to clientAssertionLifetime if expiry is unknown
// or already past, and is capped at maxDeviceAssertionLifetime.
func deviceAssertionLifetime(expiry time.Time) time.Duration {
	if expiry.IsZero() {
		return clientAssertionLifetime
	}
	remaining := time.Until(expiry)
	if remaining <= 0 {
		return clientAssertionLifetime
	}
	if remaining > maxDeviceAssertionLifetime {
		return maxDeviceAssertionLifetime
	}
	return remaining
}

// DeviceLogin runs the RFC 8628 device-authorization grant: fetch a device
// code + user code, print the verification URL and code to prompt (stderr
// only — never stdout), then poll the token endpoint until the user
// completes the flow, the device code expires, or ctx is cancelled.
func (p *Provider) DeviceLogin(ctx context.Context, scope string, prompt io.Writer, extraFields url.Values) (output.Result, error) {
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

	// DeviceAccessToken polls internally with no hook to refresh options
	// between polls, so a private_key_jwt assertion minted here must
	// outlive the whole poll loop: size it off the device code's own
	// expiry (capped at maxDeviceAssertionLifetime) rather than the
	// shorter fixed window used by the other two flows.
	assertionOpts, err := p.clientAssertionOptions(deviceAssertionLifetime(da.Expiry))
	if err != nil {
		return output.Result{}, err
	}
	tokenOpts := append(append([]oauth2.AuthCodeOption{}, opts...), assertionOpts...)

	for k, vs := range extraFields {
		for _, v := range vs {
			tokenOpts = append(tokenOpts, oauth2.SetAuthURLParam(k, v))
		}
	}

	tok, err := cfg.DeviceAccessToken(ctx, da, tokenOpts...)
	if err != nil {
		return output.Result{}, fmt.Errorf("oidc: device-code token exchange failed: %w", err)
	}

	return p.toResult(ctx, tok, "") // device-code doesn't use a nonce
}
