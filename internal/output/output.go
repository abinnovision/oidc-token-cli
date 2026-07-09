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

// allDoc is the --all JSON document shape.
type allDoc struct {
	AccessToken     string `json:"access_token,omitempty"`
	IDToken         string `json:"id_token,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	Expiry          string `json:"expiry,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

// WriteAll writes a JSON document with every available credential field to
// w. It writes nothing to w on error (the document is built in memory
// first, then written in one call).
func WriteAll(w io.Writer, r Result) error {
	doc := allDoc{
		AccessToken:     r.AccessToken,
		IDToken:         r.IDToken,
		RefreshToken:    r.RefreshToken,
		IssuedTokenType: r.IssuedTokenType,
	}
	if !r.Expiry.IsZero() {
		doc.Expiry = r.Expiry.UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
