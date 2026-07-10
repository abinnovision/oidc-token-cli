package oidc

import (
	"context"
	"fmt"
	"net/url"

	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// tokenExchangeGrantType is RFC 8693 §2.1's grant_type value.
const tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // RFC 8693 grant-type URN, not a credential

// TokenExchange performs an RFC 8693 token exchange: subjectToken (of type
// subjectTokenType) is exchanged for a new token set. It performs no
// interactive step and is never cached by the runner -- every call hits the
// token endpoint fresh, since the (issuer, client_id) cache key can't
// distinguish between different --audience/--resource targets.
//
// requestedTokenType is omitted from the request entirely when empty, per
// RFC 8693 §2.1's OPTIONAL semantics -- this package never sends a default.
// resources is sent as repeated "resource" params (RFC 8693 permits more
// than one in a single request).
func (p *Provider) TokenExchange(ctx context.Context, scope, subjectToken, subjectTokenType, requestedTokenType string, resources []string) (output.Result, error) {
	ctx = withHTTPClient(ctx)

	v := url.Values{
		"grant_type":         {tokenExchangeGrantType},
		"subject_token":      {subjectToken},
		"subject_token_type": {subjectTokenType},
	}
	if p.Audience != "" {
		v.Set("audience", p.Audience)
	}
	if scope != "" {
		v.Set("scope", scope)
	}
	if requestedTokenType != "" {
		v.Set("requested_token_type", requestedTokenType)
	}
	for _, r := range resources {
		v.Add("resource", r)
	}

	tok, err := p.postTokenRequest(ctx, p.tokenEndpoint(), v)
	if err != nil {
		return output.Result{}, fmt.Errorf("oidc: token exchange failed: %w", err)
	}
	return p.toResult(ctx, tok, "") // token exchange has no nonce concept
}
