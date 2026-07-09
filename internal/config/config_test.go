package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func noEnv(string) string { return "" }

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestParse_Defaults(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{"--issuer=https://issuer.example", "--client-id=cid"}, &stderr, Env{Getenv: noEnv})
	if err != nil {
		t.Fatalf("Parse: %v (stderr: %s)", err, stderr.String())
	}
	if cfg.Scope != DefaultScope {
		t.Errorf("Scope = %q, want %q", cfg.Scope, DefaultScope)
	}
	if cfg.GrantType != GrantAuto {
		t.Errorf("GrantType = %q, want %q", cfg.GrantType, GrantAuto)
	}
	if cfg.TokenType != TokenTypeAccessToken {
		t.Errorf("TokenType = %q, want %q (per V-M2: frp validates the OAuth2 access_token as a JWT)", cfg.TokenType, TokenTypeAccessToken)
	}
	if cfg.CacheDir == "" {
		t.Error("CacheDir must default to a non-empty path")
	}
}

func TestParse_MissingRequiredFlags(t *testing.T) {
	var stderr bytes.Buffer
	if _, err := Parse(nil, &stderr, Env{Getenv: noEnv}); err == nil {
		t.Fatal("expected error when --issuer/--client-id are missing")
	}
}

func TestParse_EnvOverridesDefaults(t *testing.T) {
	env := envFrom(map[string]string{
		"OIDC_TOKEN_SCOPE":      "openid custom-scope",
		"OIDC_TOKEN_TOKEN_TYPE": "id_token",
	})
	var stderr bytes.Buffer
	cfg, err := Parse([]string{"--issuer=https://issuer.example", "--client-id=cid"}, &stderr, Env{Getenv: env})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Scope != "openid custom-scope" {
		t.Errorf("Scope = %q, want env override", cfg.Scope)
	}
	if cfg.TokenType != TokenTypeIDToken {
		t.Errorf("TokenType = %q, want env override", cfg.TokenType)
	}
}

func TestParse_FileOverridesEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body, _ := json.Marshal(map[string]any{"scope": "openid from-file"})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	env := envFrom(map[string]string{"OIDC_TOKEN_SCOPE": "openid from-env"})
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--config=" + path,
	}, &stderr, Env{Getenv: env})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Scope != "openid from-file" {
		t.Errorf("Scope = %q, want file to win over env", cfg.Scope)
	}
}

func TestParse_FlagsOverrideFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body, _ := json.Marshal(map[string]any{"scope": "openid from-file"})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--config=" + path,
		"--scope=openid from-flag",
	}, &stderr, Env{Getenv: noEnv})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Scope != "openid from-flag" {
		t.Errorf("Scope = %q, want flag to win over file", cfg.Scope)
	}
}

func TestParse_InvalidGrantType(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=bogus",
	}, &stderr, Env{Getenv: noEnv})
	if err == nil {
		t.Fatal("expected error for invalid --grant-type")
	}
}

func TestParse_InvalidTokenType(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--token-type=bogus",
	}, &stderr, Env{Getenv: noEnv})
	if err == nil {
		t.Fatal("expected error for invalid --token-type")
	}
}

func TestParse_CacheDirOverride(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--cache-dir=/tmp/custom-cache",
	}, &stderr, Env{Getenv: noEnv})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.CacheDir != "/tmp/custom-cache" {
		t.Errorf("CacheDir = %q, want override", cfg.CacheDir)
	}
}
