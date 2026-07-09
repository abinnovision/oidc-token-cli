package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"

	"github.com/abinnovision/oidc-token-cli/internal/oidctest"
)

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func testProvider(t *testing.T) *Provider {
	t.Helper()
	m := oidctest.NewMockIssuer(t)
	p, err := Discover(context.Background(), m.Issuer(), oidctest.ClientID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return p
}

func TestApplyClientAuth_None(t *testing.T) {
	p := testProvider(t)
	cfg := p.oauth2Config("openid")
	if cfg.ClientSecret != "" {
		t.Fatalf("expected no ClientSecret for a public client, got %q", cfg.ClientSecret)
	}
	if cfg.Endpoint.AuthStyle != oauth2.AuthStyleAutoDetect {
		t.Fatalf("expected AuthStyleAutoDetect for a public client, got %v", cfg.Endpoint.AuthStyle)
	}
}

func TestApplyClientAuth_SecretBasic(t *testing.T) {
	p := testProvider(t)
	p.SetClientAuth(ClientAuthSecretBasic, "s3cr3t", nil, "", "", "")
	cfg := p.oauth2Config("openid")
	if cfg.ClientSecret != "s3cr3t" {
		t.Fatalf("expected ClientSecret %q, got %q", "s3cr3t", cfg.ClientSecret)
	}
	if cfg.Endpoint.AuthStyle != oauth2.AuthStyleInHeader {
		t.Fatalf("expected AuthStyleInHeader, got %v", cfg.Endpoint.AuthStyle)
	}
}

func TestApplyClientAuth_SecretPost(t *testing.T) {
	p := testProvider(t)
	p.SetClientAuth(ClientAuthSecretPost, "s3cr3t", nil, "", "", "")
	cfg := p.oauth2Config("openid")
	if cfg.ClientSecret != "s3cr3t" {
		t.Fatalf("expected ClientSecret %q, got %q", "s3cr3t", cfg.ClientSecret)
	}
	if cfg.Endpoint.AuthStyle != oauth2.AuthStyleInParams {
		t.Fatalf("expected AuthStyleInParams, got %v", cfg.Endpoint.AuthStyle)
	}
}

func TestApplyClientAuth_PrivateKeyJWT_LeavesOauth2ConfigUnset(t *testing.T) {
	p := testProvider(t)
	key := generateTestKey(t)
	p.SetClientAuth(ClientAuthPrivateKeyJWT, "", key, "", jose.RS256, "")
	cfg := p.oauth2Config("openid")
	if cfg.ClientSecret != "" {
		t.Fatalf("expected no ClientSecret for private_key_jwt, got %q", cfg.ClientSecret)
	}
	if cfg.Endpoint.AuthStyle != oauth2.AuthStyleAutoDetect {
		t.Fatalf("expected AuthStyleAutoDetect for private_key_jwt (assertion is a separate param), got %v", cfg.Endpoint.AuthStyle)
	}
}

func TestSignClientAssertion_ClaimsAndFreshness(t *testing.T) {
	p := testProvider(t)
	key := generateTestKey(t)
	p.SetClientAuth(ClientAuthPrivateKeyJWT, "", key, "test-kid", jose.RS256, "")

	before := time.Now()
	a1, err := p.signClientAssertion(clientAssertionLifetime)
	if err != nil {
		t.Fatalf("signClientAssertion: %v", err)
	}
	a2, err := p.signClientAssertion(clientAssertionLifetime)
	if err != nil {
		t.Fatalf("signClientAssertion: %v", err)
	}

	tok, err := jwt.ParseSigned(a1, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	if len(tok.Headers) != 1 || tok.Headers[0].KeyID != "test-kid" {
		t.Fatalf("expected kid header %q, got headers %+v", "test-kid", tok.Headers)
	}

	var claims jwt.Claims
	if err := tok.Claims(&key.PublicKey, &claims); err != nil {
		t.Fatalf("verify signature: %v", err)
	}
	if claims.Issuer != p.ClientID || claims.Subject != p.ClientID {
		t.Fatalf("expected iss/sub == %q, got iss=%q sub=%q", p.ClientID, claims.Issuer, claims.Subject)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != p.tokenEndpoint() {
		t.Fatalf("expected aud == [%q], got %v", p.tokenEndpoint(), claims.Audience)
	}
	if claims.ID == "" {
		t.Fatal("expected a non-empty jti")
	}
	if claims.Expiry == nil || claims.IssuedAt == nil {
		t.Fatal("expected exp and iat to be set")
	}
	if claims.Expiry.Time().Before(before.Add(clientAssertionLifetime - time.Second)) {
		t.Fatalf("expected exp to be roughly now+%s, got %v (before=%v)", clientAssertionLifetime, claims.Expiry.Time(), before)
	}

	tok2, err := jwt.ParseSigned(a2, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("ParseSigned (second assertion): %v", err)
	}
	var claims2 jwt.Claims
	if err := tok2.Claims(&key.PublicKey, &claims2); err != nil {
		t.Fatalf("verify signature (second assertion): %v", err)
	}
	if claims2.ID == claims.ID {
		t.Fatalf("expected distinct jti across calls, got %q both times", claims.ID)
	}
}

func TestSignClientAssertion_AudienceOverride(t *testing.T) {
	p := testProvider(t)
	key := generateTestKey(t)
	p.SetClientAuth(ClientAuthPrivateKeyJWT, "", key, "", jose.RS256, "https://issuer.example/custom-audience")

	assertion, err := p.signClientAssertion(clientAssertionLifetime)
	if err != nil {
		t.Fatalf("signClientAssertion: %v", err)
	}
	tok, err := jwt.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	var claims jwt.Claims
	if err := tok.Claims(&key.PublicKey, &claims); err != nil {
		t.Fatalf("verify signature: %v", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "https://issuer.example/custom-audience" {
		t.Fatalf("expected overridden aud, got %v", claims.Audience)
	}
}
