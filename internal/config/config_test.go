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
	"github.com/abinnovision/oidc-token-cli/internal/grant"
	"github.com/abinnovision/oidc-token-cli/internal/grant/authcode"
	"github.com/abinnovision/oidc-token-cli/internal/grant/devicecode"
	"github.com/abinnovision/oidc-token-cli/internal/grant/tokenexchange"
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

func testGrants() []grant.Grant {
	return []grant.Grant{authcode.New(), devicecode.New(), tokenexchange.New()}
}

func noEnv(string) string { return "" }

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestParse_Defaults(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{"--issuer=https://issuer.example", "--client-id=cid"}, &stderr, Env{Getenv: noEnv}, testGrants())
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
	if cfg.TokenStoreDir == "" {
		t.Error("TokenStoreDir must default to a non-empty path")
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
	if _, err := Parse(nil, &stderr, Env{Getenv: noEnv}, testGrants()); err == nil {
		t.Fatal("expected error when --issuer/--client-id are missing")
	}
}

func TestParse_EnvOverridesDefaults(t *testing.T) {
	env := envFrom(map[string]string{
		"OIDC_TOKEN_SCOPE":      "openid custom-scope",
		"OIDC_TOKEN_TOKEN_TYPE": "id_token",
	})
	var stderr bytes.Buffer
	cfg, err := Parse([]string{"--issuer=https://issuer.example", "--client-id=cid"}, &stderr, Env{Getenv: env}, testGrants())
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
	}, &stderr, Env{Getenv: env}, testGrants())
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
	}, &stderr, Env{Getenv: noEnv}, testGrants())
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
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err == nil {
		t.Fatal("expected error for invalid --grant-type")
	}
}

func TestParse_InvalidTokenType(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--token-type=bogus",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err == nil {
		t.Fatal("expected error for invalid --token-type")
	}
}

func TestParse_TokenStoreDirOverride(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--token-store-dir=/tmp/custom-cache",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.TokenStoreDir != "/tmp/custom-cache" {
		t.Errorf("TokenStoreDir = %q, want override", cfg.TokenStoreDir)
	}
}

func TestParse_TokenStoreFlag(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--token-store=keychain",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
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
	}, &stderr, Env{Getenv: env}, testGrants())
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
	}, &stderr, Env{Getenv: env}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.TokenStore != cache.BackendKeychain {
		t.Errorf("TokenStore = %q, want flag to win over env", cfg.TokenStore)
	}
}

func TestParse_TokenStoreNone(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--token-store=none",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.TokenStore != cache.BackendNone {
		t.Errorf("TokenStore = %q, want none", cfg.TokenStore)
	}
}

func TestParse_TokenStoreNone_SkipsDefaultDirResolution(t *testing.T) {
	// A broken $HOME/$XDG_CACHE_HOME must not fail Parse when caching is
	// explicitly disabled, since cache.DefaultDir is never consulted.
	env := envFrom(map[string]string{"HOME": "", "XDG_CACHE_HOME": ""})
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--token-store=none",
	}, &stderr, Env{Getenv: env}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.TokenStoreDir != "" {
		t.Errorf("TokenStoreDir = %q, want empty when --token-store=none", cfg.TokenStoreDir)
	}
}

func TestParse_InvalidTokenStore(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--token-store=bogus",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err == nil {
		t.Fatal("expected error for invalid --token-store")
	}
}

func TestParse_LogoutFlag(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--logout",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
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
	}, &stderr, Env{Getenv: env}, testGrants())
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
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err == nil {
		t.Fatal("expected error for invalid --client-auth-method")
	}
}

func TestParse_ClientSecretBasic_RequiresSecret(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--client-auth-method=client_secret_basic",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err == nil {
		t.Fatal("expected error when client_secret_basic is selected without --client-secret")
	}
}

func TestParse_ClientSecretBasic_WithSecret(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid",
		"--client-auth-method=client_secret_basic", "--client-secret=s3cr3t",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
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
	}, &stderr, Env{Getenv: noEnv}, testGrants())
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
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err == nil {
		t.Fatal("expected error when --client-secret is set without --client-auth-method")
	}
}

func TestParse_PrivateKeyJWT_RequiresKeyFile(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--client-auth-method=private_key_jwt",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
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
	}, &stderr, Env{Getenv: noEnv}, testGrants())
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
	}, &stderr, Env{Getenv: noEnv}, testGrants())
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
	}, &stderr, Env{Getenv: noEnv}, testGrants())
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
	cfg, err := Parse([]string{"--issuer=https://issuer.example", "--client-id=cid"}, &stderr, Env{Getenv: env}, testGrants())
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
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.ClientAssertionAudience != "https://issuer.example/custom-aud" {
		t.Errorf("ClientAssertionAudience = %q, want override", cfg.ClientAssertionAudience)
	}
}

func TestParse_TokenExchange_RequiresSubjectToken(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err == nil {
		t.Fatal("expected error when --grant-type=token-exchange is set without --subject-token")
	}
}

func TestParse_TokenExchange_WithSubjectToken_Succeeds(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
		"--subject-token=sub-tok",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.SubjectToken != "sub-tok" {
		t.Errorf("SubjectToken = %q, want sub-tok", cfg.SubjectToken)
	}
	if cfg.SubjectTokenType != DefaultSubjectTokenType {
		t.Errorf("SubjectTokenType = %q, want default %q", cfg.SubjectTokenType, DefaultSubjectTokenType)
	}
}

func TestParse_TokenExchange_GitHubActionsSource_DefaultsIDTokenType(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
		"--subject-token-source=github-actions",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.SubjectTokenType != DefaultSubjectTokenTypeGitHubActions {
		t.Errorf("SubjectTokenType = %q, want github-actions default %q", cfg.SubjectTokenType, DefaultSubjectTokenTypeGitHubActions)
	}
}

func TestParse_TokenExchange_GitHubActionsSource_ExplicitTypeWins(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
		"--subject-token-source=github-actions",
		"--subject-token-type=" + DefaultSubjectTokenType,
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.SubjectTokenType != DefaultSubjectTokenType {
		t.Errorf("SubjectTokenType = %q, want explicit override %q", cfg.SubjectTokenType, DefaultSubjectTokenType)
	}
}

func TestParse_SubjectTokenFile_TakesPrecedenceOverFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subject-token")
	if err := os.WriteFile(path, []byte("file-subject-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
		"--subject-token=flag-subject-token",
		"--subject-token-file=" + path,
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.SubjectToken != "file-subject-token" {
		t.Errorf("SubjectToken = %q, want the file's contents (trailing newline trimmed) to win over --subject-token", cfg.SubjectToken)
	}
}

func TestParse_SubjectToken_EnvOverridesDefaults(t *testing.T) {
	env := envFrom(map[string]string{
		"OIDC_TOKEN_SUBJECT_TOKEN":      "env-subject-token",
		"OIDC_TOKEN_SUBJECT_TOKEN_TYPE": "urn:ietf:params:oauth:token-type:id_token",
	})
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
	}, &stderr, Env{Getenv: env}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.SubjectToken != "env-subject-token" {
		t.Errorf("SubjectToken = %q, want env override", cfg.SubjectToken)
	}
	if cfg.SubjectTokenType != "urn:ietf:params:oauth:token-type:id_token" {
		t.Errorf("SubjectTokenType = %q, want env override", cfg.SubjectTokenType)
	}
}

func TestParse_Resource_Repeatable(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
		"--subject-token=sub-tok",
		"--resource=https://a.example/", "--resource=https://b.example/",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"https://a.example/", "https://b.example/"}
	if len(cfg.Resources) != len(want) || cfg.Resources[0] != want[0] || cfg.Resources[1] != want[1] {
		t.Errorf("Resources = %v, want %v", cfg.Resources, want)
	}
}

func TestParse_RequestedTokenType_OptionalOmitted(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
		"--subject-token=sub-tok",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.RequestedTokenType != "" {
		t.Errorf("RequestedTokenType = %q, want empty when unset", cfg.RequestedTokenType)
	}
}

func TestParse_SubjectTokenWithoutGrantType_Errors(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--subject-token=sub-tok",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err == nil {
		t.Fatal("expected error when --subject-token is set without --grant-type=token-exchange")
	}
}

func TestParse_SubjectTokenSource_GitHubActions_Succeeds(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
		"--subject-token-source=github-actions",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.SubjectTokenSource != SubjectTokenSourceGitHubActions {
		t.Errorf("SubjectTokenSource = %q, want github-actions", cfg.SubjectTokenSource)
	}
	if cfg.SubjectToken != "" {
		t.Errorf("SubjectToken = %q, want empty when resolved via --subject-token-source", cfg.SubjectToken)
	}
}

func TestParse_SubjectTokenSource_MutuallyExclusiveWithSubjectToken(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
		"--subject-token-source=github-actions", "--subject-token=sub-tok",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err == nil {
		t.Fatal("expected error when --subject-token-source and --subject-token are both set")
	}
}

func TestParse_SubjectTokenSource_MutuallyExclusiveWithEnvSubjectToken(t *testing.T) {
	env := envFrom(map[string]string{"OIDC_TOKEN_SUBJECT_TOKEN": "env-subject-token"})
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
		"--subject-token-source=github-actions",
	}, &stderr, Env{Getenv: env}, testGrants())
	if err == nil {
		t.Fatal("expected error when --subject-token-source is set and $OIDC_TOKEN_SUBJECT_TOKEN is also set")
	}
}

func TestParse_SubjectTokenSource_RequiresTokenExchangeGrant(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=auto",
		"--subject-token-source=github-actions",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err == nil {
		t.Fatal("expected error when --subject-token-source is set without --grant-type=token-exchange")
	}
}

func TestParse_SubjectTokenSource_UnknownValue_Errors(t *testing.T) {
	var stderr bytes.Buffer
	_, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
		"--subject-token-source=gitlab-ci",
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err == nil {
		t.Fatal("expected error for an unknown --subject-token-source value")
	}
}

func TestParse_SubjectTokenSource_EnvVar(t *testing.T) {
	env := envFrom(map[string]string{"OIDC_TOKEN_SUBJECT_TOKEN_SOURCE": "github-actions"})
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
	}, &stderr, Env{Getenv: env}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.SubjectTokenSource != SubjectTokenSourceGitHubActions {
		t.Errorf("SubjectTokenSource = %q, want env override", cfg.SubjectTokenSource)
	}
}

func TestParse_SubjectTokenSource_FileConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body, _ := json.Marshal(map[string]any{"subject_token_source": "github-actions"})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cfg, err := Parse([]string{
		"--issuer=https://issuer.example", "--client-id=cid", "--grant-type=token-exchange",
		"--config=" + path,
	}, &stderr, Env{Getenv: noEnv}, testGrants())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.SubjectTokenSource != SubjectTokenSourceGitHubActions {
		t.Errorf("SubjectTokenSource = %q, want file config value", cfg.SubjectTokenSource)
	}
}
