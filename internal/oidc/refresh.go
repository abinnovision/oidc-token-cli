package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// Refresh silently exchanges refreshToken for a new token set. It performs
// no interactive step — a failure here (expired/revoked/rotated-away
// refresh token) is the runner's signal to fall back to interactive login.
func (p *Provider) Refresh(ctx context.Context, scope, refreshToken string) (output.Result, error) {
	ctx = withHTTPClient(ctx)
	cfg := p.oauth2Config(scope)

	if p.clientAuth.method == ClientAuthPrivateKeyJWT {
		return p.refreshWithAssertion(ctx, cfg, refreshToken)
	}

	// client_secret_basic/client_secret_post/none: oauth2.Config.ClientSecret
	// and Endpoint.AuthStyle (set by applyClientAuth, inside oauth2Config)
	// are enough -- cfg.TokenSource handles auth transparently.
	src := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	tok, err := src.Token()
	if err != nil {
		return output.Result{}, fmt.Errorf("oidc: refresh failed: %w", err)
	}
	return p.toResult(ctx, tok, "") // refresh doesn't use a nonce
}

// refreshWithAssertion performs the refresh_token grant manually, since
// oauth2.Config.TokenSource has no hook to attach a per-request
// client_assertion (unlike Exchange/DeviceAccessToken, which accept
// AuthCodeOption). Errors are surfaced as *oauth2.RetrieveError so
// authflow.isPerClientRejection's errors.As check keeps working unchanged.
func (p *Provider) refreshWithAssertion(ctx context.Context, cfg *oauth2.Config, refreshToken string) (output.Result, error) {
	assertion, err := p.signClientAssertion(clientAssertionLifetime)
	if err != nil {
		return output.Result{}, err
	}

	v := url.Values{
		"grant_type":            {"refresh_token"},
		"refresh_token":         {refreshToken},
		"client_assertion_type": {clientAssertionType},
		"client_assertion":      {assertion},
	}

	tok, err := postTokenRequest(ctx, cfg.Endpoint.TokenURL, v)
	if err != nil {
		return output.Result{}, fmt.Errorf("oidc: refresh failed: %w", err)
	}
	return p.toResult(ctx, tok, "")
}

// tokenResponse is the RFC 6749 §5.1/§5.2 token-endpoint response shape.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int64  `json:"expires_in"`
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

// postTokenRequest POSTs v to tokenURL and parses the response, mirroring
// the minimal subset of x/oauth2's internal token-retrieval logic this
// package needs for the one flow (private_key_jwt refresh) that can't go
// through oauth2.Config directly.
func postTokenRequest(ctx context.Context, tokenURL string, v url.Values) (*oauth2.Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, &oauth2.RetrieveError{Response: resp, Body: body}
		}
		return nil, fmt.Errorf("parse token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 || tr.Error != "" {
		return nil, &oauth2.RetrieveError{
			Response:         resp,
			Body:             body,
			ErrorCode:        tr.Error,
			ErrorDescription: tr.ErrorDescription,
			ErrorURI:         tr.ErrorURI,
		}
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("oidc: token response missing access_token")
	}

	tok := &oauth2.Token{
		AccessToken:  tr.AccessToken,
		TokenType:    tr.TokenType,
		RefreshToken: tr.RefreshToken,
	}
	if tr.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	if tr.IDToken != "" {
		tok = tok.WithExtra(map[string]any{"id_token": tr.IDToken})
	}
	return tok, nil
}
