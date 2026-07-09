package output

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestWriteBare_AccessToken(t *testing.T) {
	var buf bytes.Buffer
	r := Result{AccessToken: "abc.def.ghi"}
	if err := WriteBare(&buf, r, TokenTypeAccessToken); err != nil {
		t.Fatalf("WriteBare: %v", err)
	}
	if got := buf.String(); got != "abc.def.ghi" {
		t.Fatalf("stdout = %q, want exact token bytes with no trailing newline", got)
	}
}

func TestWriteBare_IDToken(t *testing.T) {
	var buf bytes.Buffer
	r := Result{IDToken: "id.tok.en"}
	if err := WriteBare(&buf, r, TokenTypeIDToken); err != nil {
		t.Fatalf("WriteBare: %v", err)
	}
	if got := buf.String(); got != "id.tok.en" {
		t.Fatalf("stdout = %q, want %q", got, "id.tok.en")
	}
}

func TestWriteBare_MissingTokenType_EmptyBufferOnError(t *testing.T) {
	var buf bytes.Buffer
	r := Result{AccessToken: "abc"} // no id_token
	err := WriteBare(&buf, r, TokenTypeIDToken)
	if err == nil {
		t.Fatal("expected error when requested token type is absent")
	}
	if buf.Len() != 0 {
		t.Fatalf("buffer must stay empty on error, got %q", buf.String())
	}
}

func TestWriteBare_UnknownTokenType(t *testing.T) {
	var buf bytes.Buffer
	err := WriteBare(&buf, Result{AccessToken: "abc", IDToken: "def"}, TokenType("bogus"))
	if err == nil {
		t.Fatal("expected error for unknown token type")
	}
	if buf.Len() != 0 {
		t.Fatalf("buffer must stay empty on error, got %q", buf.String())
	}
}

func TestWriteAll_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	r := Result{
		AccessToken:  "at",
		IDToken:      "it",
		RefreshToken: "rt",
		Expiry:       time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	if err := WriteAll(&buf, r); err != nil {
		t.Fatalf("WriteAll: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\nraw: %s", err, buf.String())
	}
	if doc["access_token"] != "at" || doc["id_token"] != "it" || doc["refresh_token"] != "rt" {
		t.Fatalf("unexpected JSON document: %v", doc)
	}
}

func TestWriteAll_OmitsEmptyFields(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteAll(&buf, Result{AccessToken: "at"}); err != nil {
		t.Fatalf("WriteAll: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if _, ok := doc["id_token"]; ok {
		t.Fatalf("expected id_token to be omitted, got %v", doc)
	}
	if _, ok := doc["refresh_token"]; ok {
		t.Fatalf("expected refresh_token to be omitted, got %v", doc)
	}
}

func TestSelect(t *testing.T) {
	r := Result{AccessToken: "at", IDToken: "it"}
	if tok, ok := Select(r, TokenTypeAccessToken); !ok || tok != "at" {
		t.Fatalf("Select(access_token) = %q, %v", tok, ok)
	}
	if tok, ok := Select(r, TokenTypeIDToken); !ok || tok != "it" {
		t.Fatalf("Select(id_token) = %q, %v", tok, ok)
	}
	if _, ok := Select(Result{}, TokenTypeAccessToken); ok {
		t.Fatal("Select on empty Result must report not-ok")
	}
}
