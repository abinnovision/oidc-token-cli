package oidc

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"

	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// Refresh silently exchanges refreshToken for a new token set. It performs
// no interactive step — a failure here (expired/revoked/rotated-away
// refresh token) is the runner's signal to fall back to interactive login.
func (p *Provider) Refresh(ctx context.Context, scope, refreshToken string) (output.Result, error) {
	ctx = withHTTPClient(ctx)
	cfg := p.oauth2Config(scope)
	src := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	tok, err := src.Token()
	if err != nil {
		return output.Result{}, fmt.Errorf("oidc: refresh failed: %w", err)
	}
	return p.toResult(ctx, tok, "") // refresh doesn't use a nonce
}
