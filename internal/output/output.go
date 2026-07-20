package output

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// TokenType selects which credential field a caller wants printed.
type TokenType string

const (
	TokenTypeAccessToken TokenType = "access_token"
	TokenTypeIDToken     TokenType = "id_token"
)

// DefaultExecCredentialAPIVersion is used by WriteExecCredential when no
// apiVersion is supplied.
const DefaultExecCredentialAPIVersion = "client.authentication.k8s.io/v1"

// Result carries whatever credential material a successful run produced.
type Result struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	Expiry       time.Time
	// IDTokenError is set when the issuer returned an id_token that failed
	// verification; IDToken is left empty in that case. Not fatal by
	// itself — the runner decides based on --token-type. Never persisted
	// to the cache.
	IDTokenError error
	// IssuedTokenType is RFC 8693 §2.2.1's issued_token_type, populated only
	// by a token-exchange response; empty for every other grant.
	IssuedTokenType string
	// Extra holds any non-standard extension fields from the token response.
	Extra map[string]any
}

// Select returns the token string for the requested type and whether it was
// non-empty. Callers must treat ok==false as a hard failure: never print an
// empty token.
func Select(r Result, tt TokenType) (string, bool) {
	switch tt {
	case TokenTypeIDToken:
		return r.IDToken, r.IDToken != ""
	case TokenTypeAccessToken:
		return r.AccessToken, r.AccessToken != ""
	default:
		return "", false
	}
}

// WriteBare writes exactly the selected token's bytes to w, no trailing
// newline. It writes nothing to w on error.
func WriteBare(w io.Writer, r Result, tt TokenType) error {
	token, ok := Select(r, tt)
	if !ok {
		return fmt.Errorf("output: no %s available", tt)
	}
	_, err := io.WriteString(w, token)
	return err
}

// WriteAll writes a JSON document with every available credential field to
// w. It writes nothing to w on error (the document is built in memory
// first, then written in one call).
func WriteAll(w io.Writer, r Result) error {
	doc := map[string]any{}
	if r.AccessToken != "" {
		doc["access_token"] = r.AccessToken
	}
	if r.IDToken != "" {
		doc["id_token"] = r.IDToken
	}
	if r.RefreshToken != "" {
		doc["refresh_token"] = r.RefreshToken
	}
	if !r.Expiry.IsZero() {
		doc["expiry"] = r.Expiry.UTC().Format(time.RFC3339)
	}
	if r.IssuedTokenType != "" {
		doc["issued_token_type"] = r.IssuedTokenType
	}
	for k, v := range r.Extra {
		doc[k] = v
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// WriteExecCredential writes a Kubernetes client.authentication.k8s.io
// ExecCredential document to w, with the selected token as status.token. It
// writes nothing to w on error (the document is built in memory first, then
// written in one call). apiVersion defaults to
// DefaultExecCredentialAPIVersion when empty.
func WriteExecCredential(w io.Writer, r Result, tt TokenType, apiVersion string) error {
	token, ok := Select(r, tt)
	if !ok {
		return fmt.Errorf("output: no %s available", tt)
	}
	if apiVersion == "" {
		apiVersion = DefaultExecCredentialAPIVersion
	}

	status := map[string]any{"token": token}
	if !r.Expiry.IsZero() {
		status["expirationTimestamp"] = r.Expiry.UTC().Format(time.RFC3339)
	}
	doc := map[string]any{
		"apiVersion": apiVersion,
		"kind":       "ExecCredential",
		"status":     status,
	}

	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// execCredentialEnv is the shape of $KUBERNETES_EXEC_INFO that kubectl sets
// when invoking an exec credential plugin.
type execCredentialEnv struct {
	APIVersion string `json:"apiVersion"`
}

// ExecCredentialAPIVersion resolves the apiVersion for WriteExecCredential
// from $KUBERNETES_EXEC_INFO, falling back to DefaultExecCredentialAPIVersion
// when the env var is unset, unparsable, or lacks an apiVersion field.
// getenv may be nil.
func ExecCredentialAPIVersion(getenv func(string) string) string {
	if getenv == nil {
		return DefaultExecCredentialAPIVersion
	}
	raw := getenv("KUBERNETES_EXEC_INFO")
	if raw == "" {
		return DefaultExecCredentialAPIVersion
	}
	var info execCredentialEnv
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		return DefaultExecCredentialAPIVersion
	}
	if info.APIVersion == "" {
		return DefaultExecCredentialAPIVersion
	}
	return info.APIVersion
}
