package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	upstream "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// authCodeTimeout bounds the whole authcode+PKCE flow (waiting for the
// user to complete login in a browser) when the caller's context has no
// deadline of its own, so this can never hang forever.
const authCodeTimeout = 5 * time.Minute

// AuthCodeLogin runs the authorization_code+PKCE grant via a one-shot
// loopback HTTP callback server bound to 127.0.0.1, never "localhost"
// (RFC 8252 §8.3).
//
// port selects the callback's TCP port: 0 for an ephemeral port, or a fixed
// port for IdPs that require an exactly-registered redirect URI.
// openBrowser, if non-nil, is invoked with the authorization URL. prompt
// receives warnings (e.g. the browser failing to open); hint receives the
// "visit this URL" fallback text and is nil when nobody is at the terminal.
func (p *Provider) AuthCodeLogin(ctx context.Context, scope string, port int, openBrowser func(u string) error, prompt, hint io.Writer, extraFields url.Values) (output.Result, error) {
	if !p.SupportsGrant("authorization_code") {
		return output.Result{}, fmt.Errorf("oidc: issuer %s does not support the authorization_code grant (issuer advertises: %s)", p.Issuer, p.AdvertisedGrants())
	}
	if _, err := p.codeChallengeMethod(); err != nil {
		return output.Result{}, err
	}

	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, authCodeTimeout)
		defer cancel()
	}
	ctx = withHTTPClient(ctx)

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return output.Result{}, fmt.Errorf("oidc: bind loopback callback listener: %w", err)
	}

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		return output.Result{}, fmt.Errorf("oidc: unexpected listener address type %T", ln.Addr())
	}
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", tcpAddr.Port)

	cfg := p.oauth2Config(scope)
	cfg.RedirectURL = redirectURI

	verifier := oauth2.GenerateVerifier()
	state, err := randomState()
	if err != nil {
		_ = ln.Close()
		return output.Result{}, fmt.Errorf("oidc: generate state: %w", err)
	}
	nonce, err := randomState()
	if err != nil {
		_ = ln.Close()
		return output.Result{}, fmt.Errorf("oidc: generate nonce: %w", err)
	}

	// go-oidc verifies signature/iss/aud/exp but not nonce itself, so we
	// check it ourselves to bind the id_token to this specific request.
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), upstream.Nonce(nonce)}
	if p.Audience != "" {
		opts = append(opts, oauth2.SetAuthURLParam("audience", p.Audience))
	}
	authURL := cfg.AuthCodeURL(state, opts...)

	if openBrowser != nil {
		if err := openBrowser(authURL); err != nil && prompt != nil {
			fmt.Fprintf(prompt, "warning: could not open a browser automatically: %v\n", err)
		}
	}
	if hint != nil {
		fmt.Fprintf(hint, "To sign in, visit:\n\n  %s\n\n", authURL)
	}

	// awaitCallback itself rejects any request whose state doesn't match
	// ours (without ending the flow), so by the time it returns
	// successfully the state has already been validated.
	code, err := awaitCallback(ctx, ln, state)
	if err != nil {
		return output.Result{}, err
	}

	exchangeOpts := []oauth2.AuthCodeOption{oauth2.VerifierOption(verifier)}
	assertionOpts, err := p.clientAssertionOptions(clientAssertionLifetime)
	if err != nil {
		return output.Result{}, err
	}
	exchangeOpts = append(exchangeOpts, assertionOpts...)

	for k, vs := range extraFields {
		for _, v := range vs {
			exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam(k, v))
		}
	}

	tok, err := cfg.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return output.Result{}, fmt.Errorf("oidc: authorization code exchange failed: %w", err)
	}
	return p.toResult(ctx, tok, nonce)
}

func randomState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
