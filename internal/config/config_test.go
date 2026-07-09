package config

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/abinnovision/oidc-token-cli/internal/cache"
)

// writeTestPrivateKeyPEM generates an RSA key, PEM-encodes it as PKCS#8, and
// writes it to a file in t.TempDir(), returning the file path.
func writeTestPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

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
	if cfg.TokenStore != cache.BackendAuto {
		t.Errorf("TokenStore = %q, want %q", cfg.TokenStore, cache.BackendAuto)
	}
	if cfg.Logout {
		t.Error("Logout must default to false")
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

func TestParse_TokenStoreFlag(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--token-store=keychain",
	}, &stderr, Env{Getenv: noEnv})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.TokenStore != cache.BackendKeychain {
		t.Errorf("TokenStore = %q, want keychain", cfg.TokenStore)
	}
}

func TestParse_TokenStoreEnv(t *testing.T) {
	env := envFrom(map[string]string{"OIDC_TOKEN_STORE": "file"})
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid",
	}, &stderr, Env{Getenv: env})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.TokenStore != cache.BackendFile {
		t.Errorf("TokenStore = %q, want file", cfg.TokenStore)
	}
}

func TestParse_TokenStoreFlagOverridesEnv(t *testing.T) {
	env := envFrom(map[string]string{"OIDC_TOKEN_STORE": "file"})
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--token-store=keychain",
	}, &stderr, Env{Getenv: env})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.TokenStore != cache.BackendKeychain {
		t.Errorf("TokenStore = %q, want flag to win over env", cfg.TokenStore)
	}
}

func TestParse_InvalidTokenStore(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--token-store=bogus",
	}, &stderr, Env{Getenv: noEnv})
	if err == nil {
		t.Fatal("expected error for invalid --token-store")
	}
}

func TestParse_LogoutFlag(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--logout",
	}, &stderr, Env{Getenv: noEnv})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.Logout {
		t.Error("Logout = false, want true")
	}
}

func TestParse_LogoutEnv(t *testing.T) {
	env := envFrom(map[string]string{"OIDC_TOKEN_LOGOUT": "1"})
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid",
	}, &stderr, Env{Getenv: env})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.Logout {
		t.Error("Logout = false, want true from env")
	}
}

func TestParse_ClientAuthMethod_InvalidMethod(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--client-auth-method=bogus",
	}, &stderr, Env{Getenv: noEnv})
	if err == nil {
		t.Fatal("expected error for invalid --client-auth-method")
	}
}

func TestParse_ClientSecretBasic_RequiresSecret(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--client-auth-method=client_secret_basic",
	}, &stderr, Env{Getenv: noEnv})
	if err == nil {
		t.Fatal("expected error when client_secret_basic is selected without --client-secret")
	}
}

func TestParse_ClientSecretBasic_WithSecret(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid",
		"--client-auth-method=client_secret_basic", "--client-secret=s3cr3t",
	}, &stderr, Env{Getenv: noEnv})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.ClientAuthMethod != ClientAuthSecretBasic {
		t.Errorf("ClientAuthMethod = %q, want %q", cfg.ClientAuthMethod, ClientAuthSecretBasic)
	}
	if cfg.ClientSecret != "s3cr3t" {
		t.Errorf("ClientSecret = %q, want %q", cfg.ClientSecret, "s3cr3t")
	}
}

func TestParse_ClientSecretFile_TakesPrecedenceOverFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid",
		"--client-auth-method=client_secret_post",
		"--client-secret=flag-secret",
		"--client-secret-file=" + path,
	}, &stderr, Env{Getenv: noEnv})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.ClientSecret != "file-secret" {
		t.Errorf("ClientSecret = %q, want the file's contents (trailing newline trimmed) to win over --client-secret", cfg.ClientSecret)
	}
}

func TestParse_ClientSecretWithoutMethod_Errors(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--client-secret=s3cr3t",
	}, &stderr, Env{Getenv: noEnv})
	if err == nil {
		t.Fatal("expected error when --client-secret is set without --client-auth-method")
	}
}

func TestParse_PrivateKeyJWT_RequiresKeyFile(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--client-auth-method=private_key_jwt",
	}, &stderr, Env{Getenv: noEnv})
	if err == nil {
		t.Fatal("expected error when private_key_jwt is selected without --private-key-file")
	}
}

func TestParse_PrivateKeyJWT_InvalidAlg(t *testing.T) {
	path := writeTestPrivateKeyPEM(t)
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid",
		"--client-auth-method=private_key_jwt", "--private-key-file=" + path, "--private-key-alg=bogus",
	}, &stderr, Env{Getenv: noEnv})
	if err == nil {
		t.Fatal("expected error for invalid --private-key-alg")
	}
}

func TestParse_PrivateKeyJWT_ParsesKeyAndDefaultsAlg(t *testing.T) {
	path := writeTestPrivateKeyPEM(t)
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid",
		"--client-auth-method=private_key_jwt", "--private-key-file=" + path,
	}, &stderr, Env{Getenv: noEnv})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.PrivateKeySigningAlg != DefaultPrivateKeySigningAlg {
		t.Errorf("PrivateKeySigningAlg = %q, want default %q", cfg.PrivateKeySigningAlg, DefaultPrivateKeySigningAlg)
	}
	if cfg.PrivateKey == nil {
		t.Fatal("expected PrivateKeyPath to be parsed into a non-nil crypto.Signer")
	}
}

func TestParse_PrivateKeyJWT_BadPEM_Errors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("not a pem file"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid",
		"--client-auth-method=private_key_jwt", "--private-key-file=" + path,
	}, &stderr, Env{Getenv: noEnv})
	if err == nil {
		t.Fatal("expected error for a malformed --private-key-file")
	}
}

func TestParse_ClientAuthMethod_EnvOverridesDefaults(t *testing.T) {
	path := writeTestPrivateKeyPEM(t)
	env := envFrom(map[string]string{
		"OIDC_TOKEN_CLIENT_AUTH_METHOD": "private_key_jwt",
		"OIDC_TOKEN_PRIVATE_KEY_FILE":   path,
		"OIDC_TOKEN_PRIVATE_KEY_ID":     "kid-from-env",
		"OIDC_TOKEN_PRIVATE_KEY_ALG":    "ES256",
	})
	var stderr bytes.Buffer
	cfg, err := Parse([]string{"--issuer=https://issuer.example", "--client-id=cid"}, &stderr, Env{Getenv: env})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.ClientAuthMethod != ClientAuthPrivateKeyJWT {
		t.Errorf("ClientAuthMethod = %q, want env override", cfg.ClientAuthMethod)
	}
	if cfg.PrivateKeyID != "kid-from-env" {
		t.Errorf("PrivateKeyID = %q, want env override", cfg.PrivateKeyID)
	}
	if cfg.PrivateKeySigningAlg != "ES256" {
		t.Errorf("PrivateKeySigningAlg = %q, want env override", cfg.PrivateKeySigningAlg)
	}
}

func TestParse_ClientAssertionAudience_FlagOverride(t *testing.T) {
	path := writeTestPrivateKeyPEM(t)
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid",
		"--client-auth-method=private_key_jwt", "--private-key-file=" + path,
		"--client-assertion-audience=https://issuer.example/custom-aud",
	}, &stderr, Env{Getenv: noEnv})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.ClientAssertionAudience != "https://issuer.example/custom-aud" {
		t.Errorf("ClientAssertionAudience = %q, want override", cfg.ClientAssertionAudience)
	}
}
