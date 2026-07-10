package oidc

import (
	"crypto"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

// ClientAuthMethod selects how the client authenticates itself to the token
// endpoint. ClientAuthNone (the zero value) is a public client: no secret,
// no assertion -- this tool's original, and still default, behavior.
type ClientAuthMethod string

const (
	ClientAuthNone          ClientAuthMethod = ""
	ClientAuthSecretBasic   ClientAuthMethod = "client_secret_basic"
	ClientAuthSecretPost    ClientAuthMethod = "client_secret_post"
	ClientAuthPrivateKeyJWT ClientAuthMethod = "private_key_jwt"
)

// clientAssertionType is RFC 7523's client_assertion_type value for a
// signed-JWT client assertion.
const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// clientAssertionLifetime bounds how long a minted private_key_jwt
// assertion is valid for, per RFC 7523 §3. AuthCodeLogin and Refresh use
// this fixed window; DeviceLogin uses a longer, device-code-expiry-derived
// window since a single assertion must survive its whole poll loop (see
// device.go).
const clientAssertionLifetime = 5 * time.Minute

// clientAuth holds a Provider's resolved client-authentication
// configuration. The zero value is ClientAuthNone: a public client.
type clientAuth struct {
	method   ClientAuthMethod
	secret   string
	signer   crypto.Signer
	keyID    string
	alg      jose.SignatureAlgorithm
	audience string // overrides the assertion's "aud"; "" defaults to the token endpoint
}

// SetClientAuth configures how p authenticates to the token endpoint.
// Calling this with method == ClientAuthNone (or not calling it at all)
// leaves p as a public client.
func (p *Provider) SetClientAuth(method ClientAuthMethod, secret string, signer crypto.Signer, keyID string, alg jose.SignatureAlgorithm, audience string) {
	p.clientAuth = clientAuth{
		method:   method,
		secret:   secret,
		signer:   signer,
		keyID:    keyID,
		alg:      alg,
		audience: audience,
	}
}

// applyClientAuth wires client_secret_basic/client_secret_post into cfg.
// private_key_jwt and the public-client default are handled separately via
// clientAssertionOptions, since oauth2.Config has no field for a signed
// assertion.
func (p *Provider) applyClientAuth(cfg *oauth2.Config) {
	switch p.clientAuth.method {
	case ClientAuthSecretBasic:
		cfg.ClientSecret = p.clientAuth.secret
		cfg.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	case ClientAuthSecretPost:
		cfg.ClientSecret = p.clientAuth.secret
		cfg.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	default:
		// ClientAuthNone (public client) and ClientAuthPrivateKeyJWT need no
		// oauth2.Config field; the latter is handled via
		// clientAssertionOptions instead.
	}
}

// clientAssertionOptions returns the client_assertion/client_assertion_type
// token-request params for private_key_jwt, freshly minted for this single
// call -- never cached, since jti/iat/exp must be fresh per RFC 7523 §3. It
// returns nil for every other auth method.
func (p *Provider) clientAssertionOptions(lifetime time.Duration) ([]oauth2.AuthCodeOption, error) {
	if p.clientAuth.method != ClientAuthPrivateKeyJWT {
		return nil, nil
	}
	assertion, err := p.signClientAssertion(lifetime)
	if err != nil {
		return nil, err
	}
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("client_assertion_type", clientAssertionType),
		oauth2.SetAuthURLParam("client_assertion", assertion),
	}, nil
}

// signClientAssertion builds and signs a private_key_jwt client assertion
// per RFC 7523 §3: iss/sub identify the client, aud is the token endpoint
// unless ClientAssertionAudience overrides it, jti is unique per call, and
// exp is bounded by lifetime.
func (p *Provider) signClientAssertion(lifetime time.Duration) (string, error) {
	aud := p.clientAuth.audience
	if aud == "" {
		aud = p.tokenEndpoint()
	}
	jti, err := randomState()
	if err != nil {
		return "", fmt.Errorf("oidc: generate client assertion jti: %w", err)
	}

	signerKey := jose.JSONWebKey{Key: p.clientAuth.signer, Algorithm: string(p.clientAuth.alg)}
	if p.clientAuth.keyID != "" {
		signerKey.KeyID = p.clientAuth.keyID
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: p.clientAuth.alg, Key: signerKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("oidc: create client assertion signer: %w", err)
	}

	now := time.Now()
	claims := jwt.Claims{
		Issuer:   p.ClientID,
		Subject:  p.ClientID,
		Audience: jwt.Audience{aud},
		Expiry:   jwt.NewNumericDate(now.Add(lifetime)),
		IssuedAt: jwt.NewNumericDate(now),
		ID:       jti,
	}
	assertion, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("oidc: sign client assertion: %w", err)
	}
	return assertion, nil
}

// tokenEndpoint returns the discovered token endpoint URL, used as the
// client assertion's default audience.
func (p *Provider) tokenEndpoint() string {
	return p.upstream.Endpoint().TokenURL
}
