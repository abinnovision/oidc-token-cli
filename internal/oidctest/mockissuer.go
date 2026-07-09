// Package oidctest provides a minimal, configurable OIDC issuer for tests
// (discovery, jwks, device authorization, and token endpoints backed by a
// real RSA-signed JWT), shared across internal/oidc and internal/authflow.
package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// clientAssertionSigningAlgs are the JWS algorithms handleToken accepts
// when verifying a private_key_jwt client_assertion.
var clientAssertionSigningAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
}

// ClientID is the audience baked into mock-issued id_tokens; tests that
// verify an id_token must Discover using this as their client ID.
const ClientID = "test-client"

// MockAuthCode is the fixed authorization code the mock's browser
// simulation hands back to a loopback callback in authcode+PKCE tests.
const MockAuthCode = "mock-auth-code"

// MockIssuer is a minimal, configurable OIDC issuer.
type MockIssuer struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey

	mu           sync.Mutex
	deviceCodes  map[string]*mockDeviceCode
	refreshSeq   int
	refreshCalls int

	// Configurable behavior. Set these fields before the first request
	// (the mock has no synchronization around reading them).
	IssuerOverride                string // non-empty simulates a mismatched "issuer" claim
	NoDeviceEndpoint              bool
	GrantTypesSupported           []string // nil = field omitted from discovery doc
	CodeChallengeMethodsSupported []string // nil = field omitted
	PendingPolls                  int      // authorization_pending responses before success
	DeviceIntervalSeconds         int64
	DeviceExpiresInSeconds        int64
	Audience                      string
	IncludeIDToken                bool
	RefreshErr                    string        // non-empty: refresh_token grant always fails with this error
	RefreshDelay                  time.Duration // artificial latency, to widen a rotation-race window in tests
	OmitRefreshToken              bool
	AuthCodeErr                   string // non-empty: authorization_code grant always fails with this error
	OmitDeviceExpiresIn           bool   // non-compliant with RFC 8628 §3.2, but some issuers do this
	// NonceForAuthCode is embedded as the id_token's nonce claim on the
	// authorization_code grant response; this mock has no server-side
	// session state binding it to the authorization request automatically,
	// so tests set it directly.
	NonceForAuthCode string

	// RequireClientAuth, if non-empty ("client_secret_basic",
	// "client_secret_post", or "private_key_jwt"), makes handleToken
	// reject any token-endpoint request that doesn't authenticate with
	// that exact method. Empty (the default) is this mock's original,
	// permissive behavior: no client authentication is checked.
	RequireClientAuth    string
	ExpectedClientSecret string
	// ExpectedAssertionKey verifies a private_key_jwt client_assertion's
	// signature; required when RequireClientAuth == "private_key_jwt".
	ExpectedAssertionKey crypto.PublicKey

	assertionJTIs []string
}

// AssertionJTIs returns the jti claim of every private_key_jwt client
// assertion handleToken has successfully verified so far, in call order --
// used to assert freshness (no two calls reuse a jti).
func (m *MockIssuer) AssertionJTIs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.assertionJTIs...)
}

type mockDeviceCode struct {
	userCode string
	polls    int
}

// NewMockIssuer starts an httptest server and registers t.Cleanup to close
// it. Configure the returned MockIssuer's exported fields, then call
// Issuer() to get its URL before starting a flow.
func NewMockIssuer(t *testing.T) *MockIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	m := &MockIssuer{
		t:                      t,
		key:                    key,
		deviceCodes:            map[string]*mockDeviceCode{},
		DeviceIntervalSeconds:  1, // DeviceAccessToken defaults interval=0 to 5s; keep tests fast
		DeviceExpiresInSeconds: 300,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/jwks", m.handleJWKS)
	mux.HandleFunc("/device_authorization", m.handleDeviceAuthorization)
	mux.HandleFunc("/token", m.handleToken)
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {})

	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

// Issuer returns the mock server's base URL, usable as the OIDC issuer.
func (m *MockIssuer) Issuer() string {
	return m.srv.URL
}

// RefreshCallCount returns how many times the refresh_token grant handler
// has been invoked so far.
func (m *MockIssuer) RefreshCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.refreshCalls
}

func (m *MockIssuer) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := m.srv.URL
	if m.IssuerOverride != "" {
		issuer = m.IssuerOverride
	}
	doc := map[string]any{
		"issuer":                 issuer,
		"authorization_endpoint": m.srv.URL + "/authorize",
		"token_endpoint":         m.srv.URL + "/token",
		"jwks_uri":               m.srv.URL + "/jwks",
	}
	if !m.NoDeviceEndpoint {
		doc["device_authorization_endpoint"] = m.srv.URL + "/device_authorization"
	}
	if m.GrantTypesSupported != nil {
		doc["grant_types_supported"] = m.GrantTypesSupported
	}
	if m.CodeChallengeMethodsSupported != nil {
		doc["code_challenge_methods_supported"] = m.CodeChallengeMethodsSupported
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (m *MockIssuer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := jose.JSONWebKey{Key: &m.key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

func (m *MockIssuer) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	code := "device-code-" + strconv.Itoa(len(m.deviceCodes)+1)
	m.deviceCodes[code] = &mockDeviceCode{userCode: "USER-CODE"}
	m.mu.Unlock()

	resp := map[string]any{
		"device_code":      code,
		"user_code":        "USER-CODE",
		"verification_uri": m.srv.URL + "/verify",
		"interval":         m.DeviceIntervalSeconds,
	}
	if !m.OmitDeviceExpiresIn {
		resp["expires_in"] = m.DeviceExpiresInSeconds
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (m *MockIssuer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if err := m.checkClientAuth(r); err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	switch r.Form.Get("grant_type") {
	case "urn:ietf:params:oauth:grant-type:device_code":
		m.handleDeviceToken(w, r)
	case "refresh_token":
		m.handleRefreshToken(w, r)
	case "authorization_code":
		m.handleAuthCodeToken(w, r)
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

// checkClientAuth enforces RequireClientAuth against r, which must already
// have ParseForm called on it. A nil error means the request authenticated
// correctly (or RequireClientAuth is unset).
func (m *MockIssuer) checkClientAuth(r *http.Request) error {
	switch m.RequireClientAuth {
	case "":
		return nil
	case "client_secret_basic":
		id, secret, ok := r.BasicAuth()
		if !ok || id != ClientID || secret != m.ExpectedClientSecret {
			return fmt.Errorf("bad client_secret_basic credentials")
		}
		return nil
	case "client_secret_post":
		if r.Form.Get("client_id") != ClientID || r.Form.Get("client_secret") != m.ExpectedClientSecret {
			return fmt.Errorf("bad client_secret_post credentials")
		}
		return nil
	case "private_key_jwt":
		return m.checkClientAssertion(r)
	default:
		return fmt.Errorf("mock issuer: unknown RequireClientAuth %q", m.RequireClientAuth)
	}
}

func (m *MockIssuer) checkClientAssertion(r *http.Request) error {
	const wantType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	if r.Form.Get("client_assertion_type") != wantType {
		return fmt.Errorf("bad client_assertion_type")
	}
	assertion := r.Form.Get("client_assertion")
	if assertion == "" {
		return fmt.Errorf("missing client_assertion")
	}
	tok, err := jwt.ParseSigned(assertion, clientAssertionSigningAlgs)
	if err != nil {
		return fmt.Errorf("parse client_assertion: %w", err)
	}
	var claims jwt.Claims
	if err := tok.Claims(m.ExpectedAssertionKey, &claims); err != nil {
		return fmt.Errorf("verify client_assertion signature: %w", err)
	}
	if claims.Issuer != ClientID || claims.Subject != ClientID {
		return fmt.Errorf("bad iss/sub claim")
	}
	if claims.ID == "" {
		return fmt.Errorf("missing jti claim")
	}
	if err := claims.Validate(jwt.Expected{}); err != nil {
		return fmt.Errorf("invalid claims: %w", err)
	}
	m.mu.Lock()
	m.assertionJTIs = append(m.assertionJTIs, claims.ID)
	m.mu.Unlock()
	return nil
}

func (m *MockIssuer) handleAuthCodeToken(w http.ResponseWriter, r *http.Request) {
	if m.AuthCodeErr != "" {
		writeTokenError(w, http.StatusBadRequest, m.AuthCodeErr)
		return
	}
	if r.Form.Get("code") != MockAuthCode {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	m.writeTokenSuccess(w, "authcode-subject", m.NonceForAuthCode)
}

func (m *MockIssuer) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("device_code")
	m.mu.Lock()
	dc, ok := m.deviceCodes[code]
	if ok {
		dc.polls++
	}
	polls := 0
	if ok {
		polls = dc.polls
	}
	m.mu.Unlock()

	if !ok {
		writeTokenError(w, http.StatusBadRequest, "expired_token")
		return
	}
	if polls <= m.PendingPolls {
		writeTokenError(w, http.StatusBadRequest, "authorization_pending")
		return
	}

	m.writeTokenSuccess(w, "device-subject", "")
}

func (m *MockIssuer) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if m.RefreshErr != "" {
		writeTokenError(w, http.StatusBadRequest, m.RefreshErr)
		return
	}
	if m.RefreshDelay > 0 {
		time.Sleep(m.RefreshDelay)
	}
	m.mu.Lock()
	m.refreshCalls++
	m.mu.Unlock()
	m.writeTokenSuccess(w, "refresh-subject", "")
}

func (m *MockIssuer) writeTokenSuccess(w http.ResponseWriter, subject, nonce string) {
	m.mu.Lock()
	m.refreshSeq++
	seq := m.refreshSeq
	m.mu.Unlock()

	resp := map[string]any{
		"access_token": fmt.Sprintf("access-token-%d", seq),
		"token_type":   "Bearer",
		"expires_in":   3600,
	}
	if !m.OmitRefreshToken {
		resp["refresh_token"] = fmt.Sprintf("refresh-token-%d", seq)
	}
	if m.IncludeIDToken {
		idToken, err := m.signIDToken(subject, nonce)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp["id_token"] = idToken
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// nonceClaim is merged into the signed JWT alongside jwt.Claims when
// nonce is non-empty; go-jose's jwt.Claims has no built-in nonce field.
type nonceClaim struct {
	Nonce string `json:"nonce,omitempty"`
}

func (m *MockIssuer) signIDToken(subject, nonce string) (string, error) {
	signerKey := jose.JSONWebKey{Key: m.key, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signerKey}, &jose.SignerOptions{})
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}
	issuer := m.srv.URL
	if m.IssuerOverride != "" {
		issuer = m.IssuerOverride
	}
	claims := jwt.Claims{
		Issuer:   issuer,
		Subject:  subject,
		Audience: jwt.Audience{ClientID},
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	return jwt.Signed(signer).Claims(claims).Claims(nonceClaim{Nonce: nonce}).Serialize()
}

func writeTokenError(w http.ResponseWriter, status int, errCode string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": errCode})
}
