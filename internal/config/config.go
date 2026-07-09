package config

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/abinnovision/oidc-token-cli/internal/cache"
)

// GrantType selects which OAuth2 grant(s) are eligible for interactive login.
type GrantType string

const (
	GrantAuto       GrantType = "auto"
	GrantAuthCode   GrantType = "authcode"
	GrantDeviceCode GrantType = "device-code"
)

// TokenType selects which credential field is printed.
type TokenType string

const (
	TokenTypeAccessToken TokenType = "access_token"
	TokenTypeIDToken     TokenType = "id_token"
)

// ClientAuthMethod selects how the client authenticates itself to the token
// endpoint. ClientAuthNone (the default) is a public client: no secret, no
// assertion, identical to this tool's original behavior.
type ClientAuthMethod string

const (
	ClientAuthNone          ClientAuthMethod = ""
	ClientAuthSecretBasic   ClientAuthMethod = "client_secret_basic"
	ClientAuthSecretPost    ClientAuthMethod = "client_secret_post"
	ClientAuthPrivateKeyJWT ClientAuthMethod = "private_key_jwt"
)

// DefaultPrivateKeySigningAlg is used for the private_key_jwt client
// assertion when --private-key-alg isn't set.
const DefaultPrivateKeySigningAlg = "RS256"

// validSigningAlgs are the jose.SignatureAlgorithm values accepted for
// --private-key-alg.
var validSigningAlgs = map[string]jose.SignatureAlgorithm{
	"RS256": jose.RS256,
	"RS384": jose.RS384,
	"RS512": jose.RS512,
	"PS256": jose.PS256,
	"PS384": jose.PS384,
	"PS512": jose.PS512,
	"ES256": jose.ES256,
	"ES384": jose.ES384,
	"ES512": jose.ES512,
}

// DefaultScope is requested whenever the caller doesn't override --scope.
// offline_access is requested unconditionally, even from issuers that omit
// it from scopes_supported; the runner warns if no refresh_token comes back.
const DefaultScope = "openid offline_access"

// Config is the fully resolved set of identity/client + behavior knobs.
type Config struct {
	Issuer         string
	ClientID       string
	Scope          string
	Audience       string
	GrantType      GrantType
	TokenType      TokenType
	CacheDir       string
	RedirectPort   int // 0 = ephemeral loopback port (RFC 8252 default)
	NonInteractive bool
	All            bool // --all: print full JSON document instead of a bare token

	// ClientAuthMethod selects how the client authenticates to the token
	// endpoint. ClientAuthNone means a public client (this tool's original,
	// and still default, behavior).
	ClientAuthMethod ClientAuthMethod
	// ClientSecret is used by client_secret_basic/client_secret_post.
	ClientSecret string
	// PrivateKeyPath is a PEM file (PKCS#1/PKCS#8/EC) used by
	// private_key_jwt to sign the client assertion.
	PrivateKeyPath string
	// PrivateKeyID is an optional "kid" header on the client assertion,
	// for issuers that select the verification key from a registered JWKS.
	PrivateKeyID string
	// PrivateKeySigningAlg is the JWS algorithm used to sign the client
	// assertion; defaults to DefaultPrivateKeySigningAlg.
	PrivateKeySigningAlg string
	// ClientAssertionAudience overrides the "aud" claim of the
	// private_key_jwt assertion; defaults to the discovered token endpoint.
	ClientAssertionAudience string

	// PrivateKey is the parsed form of PrivateKeyPath, resolved once at
	// startup so a bad key file fails fast instead of mid-flow.
	PrivateKey crypto.Signer
}

// fileConfig mirrors Config's JSON-file representation. Every field is a
// pointer so "absent from the file" is distinguishable from "zero value".
type fileConfig struct {
	Issuer         *string `json:"issuer"`
	ClientID       *string `json:"client_id"`
	Scope          *string `json:"scope"`
	Audience       *string `json:"audience"`
	GrantType      *string `json:"grant_type"`
	TokenType      *string `json:"token_type"`
	CacheDir       *string `json:"cache_dir"`
	RedirectPort   *int    `json:"redirect_port"`
	NonInteractive *bool   `json:"non_interactive"`
	All            *bool   `json:"all"`

	ClientAuthMethod        *string `json:"client_auth_method"`
	ClientSecret            *string `json:"client_secret"`
	PrivateKeyPath          *string `json:"private_key_file"`
	PrivateKeyID            *string `json:"private_key_id"`
	PrivateKeySigningAlg    *string `json:"private_key_alg"`
	ClientAssertionAudience *string `json:"client_assertion_audience"`
}

// Env is the subset of the process environment config.Parse reads from,
// injected so tests don't depend on real process env or $HOME.
type Env struct {
	Getenv func(string) string
}

func (e Env) get(key string) string {
	if e.Getenv == nil {
		return ""
	}
	return e.Getenv(key)
}

var envKeys = struct {
	issuer, clientID, scope, audience, grantType, tokenType, cacheDir, nonInteractive                           string
	clientAuthMethod, clientSecret, privateKeyPath, privateKeyID, privateKeySigningAlg, clientAssertionAudience string
}{
	issuer:         "OIDC_TOKEN_ISSUER",
	clientID:       "OIDC_TOKEN_CLIENT_ID",
	scope:          "OIDC_TOKEN_SCOPE",
	audience:       "OIDC_TOKEN_AUDIENCE",
	grantType:      "OIDC_TOKEN_GRANT_TYPE",
	tokenType:      "OIDC_TOKEN_TOKEN_TYPE",
	cacheDir:       "OIDC_TOKEN_CACHE_DIR",
	nonInteractive: "OIDC_TOKEN_NON_INTERACTIVE",

	clientAuthMethod:        "OIDC_TOKEN_CLIENT_AUTH_METHOD",
	clientSecret:            "OIDC_TOKEN_CLIENT_SECRET",
	privateKeyPath:          "OIDC_TOKEN_PRIVATE_KEY_FILE",
	privateKeyID:            "OIDC_TOKEN_PRIVATE_KEY_ID",
	privateKeySigningAlg:    "OIDC_TOKEN_PRIVATE_KEY_ALG",
	clientAssertionAudience: "OIDC_TOKEN_CLIENT_ASSERTION_AUDIENCE",
}

// Parse builds a Config from, in ascending priority: defaults, environment
// variables, an optional --config JSON file, then explicitly-set flags.
// Flags always win; a flag the caller didn't pass on the command line never
// overrides a value from a lower-priority source.
func Parse(args []string, stderr io.Writer, env Env) (*Config, error) {
	fs := flag.NewFlagSet("oidc-token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: oidc-token [flags]\n\n")
		fmt.Fprintf(stderr, "Mint and print an OIDC token for a public or confidential OIDC client.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		configFile     = fs.String("config", "", "path to an optional JSON config file")
		issuer         = fs.String("issuer", "", "OIDC issuer URL (discovery is fetched from <issuer>/.well-known/openid-configuration)")
		clientID       = fs.String("client-id", "", "OAuth2/OIDC client ID")
		scope          = fs.String("scope", DefaultScope, "space-separated OAuth2 scopes to request")
		audience       = fs.String("audience", "", "expected audience (aud) claim; required whenever the relying party checks it")
		grantType      = fs.String("grant-type", string(GrantAuto), "auto|authcode|device-code")
		tokenType      = fs.String("token-type", string(TokenTypeAccessToken), "access_token|id_token")
		cacheDirFlag   = fs.String("cache-dir", "", "override the token cache directory (default: $XDG_CACHE_HOME/oidc-token or ~/.cache/oidc-token)")
		redirectPort   = fs.Int("redirect", 0, "fixed loopback callback port for authcode; 0 selects an ephemeral port")
		nonInteractive = fs.Bool("non-interactive", false, "fail fast instead of opening a browser or a device-code prompt")
		all            = fs.Bool("all", false, "print a JSON document with every available credential field instead of a bare token")

		clientAuthMethod        = fs.String("client-auth-method", string(ClientAuthNone), "client authentication method for the token endpoint: \"\"|client_secret_basic|client_secret_post|private_key_jwt")
		clientSecret            = fs.String("client-secret", "", "client secret for client_secret_basic/client_secret_post (prefer --client-secret-file or $"+envKeys.clientSecret+" over this flag)")
		clientSecretFile        = fs.String("client-secret-file", "", "path to a file containing the client secret (trailing newline trimmed); takes precedence over --client-secret")
		privateKeyFile          = fs.String("private-key-file", "", "PEM file (PKCS#1/PKCS#8/EC) used to sign the private_key_jwt client assertion")
		privateKeyID            = fs.String("private-key-id", "", "optional \"kid\" header on the private_key_jwt client assertion")
		privateKeyAlg           = fs.String("private-key-alg", DefaultPrivateKeySigningAlg, "JWS signing algorithm for private_key_jwt: RS256|RS384|RS512|PS256|PS384|PS512|ES256|ES384|ES512")
		clientAssertionAudience = fs.String("client-assertion-audience", "", "override the \"aud\" claim of the private_key_jwt assertion (default: the discovered token endpoint)")
	)

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	cfg := &Config{
		Scope:                DefaultScope,
		GrantType:            GrantAuto,
		TokenType:            TokenTypeAccessToken,
		PrivateKeySigningAlg: DefaultPrivateKeySigningAlg,
	}

	// 1. Environment.
	if v := env.get(envKeys.issuer); v != "" {
		cfg.Issuer = v
	}
	if v := env.get(envKeys.clientID); v != "" {
		cfg.ClientID = v
	}
	if v := env.get(envKeys.scope); v != "" {
		cfg.Scope = v
	}
	if v := env.get(envKeys.audience); v != "" {
		cfg.Audience = v
	}
	if v := env.get(envKeys.grantType); v != "" {
		cfg.GrantType = GrantType(v)
	}
	if v := env.get(envKeys.tokenType); v != "" {
		cfg.TokenType = TokenType(v)
	}
	if v := env.get(envKeys.cacheDir); v != "" {
		cfg.CacheDir = v
	}
	if v := env.get(envKeys.nonInteractive); v != "" {
		cfg.NonInteractive = v == "1" || v == "true"
	}
	if v := env.get(envKeys.clientAuthMethod); v != "" {
		cfg.ClientAuthMethod = ClientAuthMethod(v)
	}
	if v := env.get(envKeys.clientSecret); v != "" {
		cfg.ClientSecret = v
	}
	if v := env.get(envKeys.privateKeyPath); v != "" {
		cfg.PrivateKeyPath = v
	}
	if v := env.get(envKeys.privateKeyID); v != "" {
		cfg.PrivateKeyID = v
	}
	if v := env.get(envKeys.privateKeySigningAlg); v != "" {
		cfg.PrivateKeySigningAlg = v
	}
	if v := env.get(envKeys.clientAssertionAudience); v != "" {
		cfg.ClientAssertionAudience = v
	}

	// 2. Config file.
	if *configFile != "" {
		fc, err := loadFileConfig(*configFile)
		if err != nil {
			return nil, err
		}
		applyFileConfig(cfg, fc)
	}

	// 3. Explicitly-set flags only (flag.Visit skips flags left at default).
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	if explicit["issuer"] {
		cfg.Issuer = *issuer
	}
	if explicit["client-id"] {
		cfg.ClientID = *clientID
	}
	if explicit["scope"] {
		cfg.Scope = *scope
	}
	if explicit["audience"] {
		cfg.Audience = *audience
	}
	if explicit["grant-type"] {
		cfg.GrantType = GrantType(*grantType)
	}
	if explicit["token-type"] {
		cfg.TokenType = TokenType(*tokenType)
	}
	if explicit["cache-dir"] {
		cfg.CacheDir = *cacheDirFlag
	}
	if explicit["redirect"] {
		cfg.RedirectPort = *redirectPort
	}
	if explicit["non-interactive"] {
		cfg.NonInteractive = *nonInteractive
	}
	if explicit["all"] {
		cfg.All = *all
	}
	if explicit["client-auth-method"] {
		cfg.ClientAuthMethod = ClientAuthMethod(*clientAuthMethod)
	}
	if explicit["client-secret"] {
		cfg.ClientSecret = *clientSecret
	}
	if explicit["private-key-file"] {
		cfg.PrivateKeyPath = *privateKeyFile
	}
	if explicit["private-key-id"] {
		cfg.PrivateKeyID = *privateKeyID
	}
	if explicit["private-key-alg"] {
		cfg.PrivateKeySigningAlg = *privateKeyAlg
	}
	if explicit["client-assertion-audience"] {
		cfg.ClientAssertionAudience = *clientAssertionAudience
	}

	// --client-secret-file always takes precedence over --client-secret /
	// OIDC_TOKEN_CLIENT_SECRET / the config file's client_secret, since it's
	// the recommended, safer channel.
	if explicit["client-secret-file"] {
		secret, err := os.ReadFile(*clientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("config: read --client-secret-file: %w", err)
		}
		cfg.ClientSecret = strings.TrimRight(string(secret), "\n")
	}

	if cfg.CacheDir == "" {
		dir, err := cache.DefaultDir(env.get)
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		cfg.CacheDir = dir
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := cfg.resolvePrivateKey(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("config: --issuer is required")
	}
	if c.ClientID == "" {
		return fmt.Errorf("config: --client-id is required")
	}
	switch c.GrantType {
	case GrantAuto, GrantAuthCode, GrantDeviceCode:
	default:
		return fmt.Errorf("config: invalid --grant-type %q (want auto|authcode|device-code)", c.GrantType)
	}
	switch c.TokenType {
	case TokenTypeAccessToken, TokenTypeIDToken:
	default:
		return fmt.Errorf("config: invalid --token-type %q (want access_token|id_token)", c.TokenType)
	}
	switch c.ClientAuthMethod {
	case ClientAuthNone, ClientAuthSecretBasic, ClientAuthSecretPost, ClientAuthPrivateKeyJWT:
	default:
		return fmt.Errorf("config: invalid --client-auth-method %q (want \"\"|client_secret_basic|client_secret_post|private_key_jwt)", c.ClientAuthMethod)
	}
	switch c.ClientAuthMethod {
	case ClientAuthSecretBasic, ClientAuthSecretPost:
		if c.ClientSecret == "" {
			return fmt.Errorf("config: --client-auth-method=%s requires --client-secret or --client-secret-file", c.ClientAuthMethod)
		}
	case ClientAuthPrivateKeyJWT:
		if c.PrivateKeyPath == "" {
			return fmt.Errorf("config: --client-auth-method=private_key_jwt requires --private-key-file")
		}
		if _, ok := validSigningAlgs[c.PrivateKeySigningAlg]; !ok {
			return fmt.Errorf("config: invalid --private-key-alg %q", c.PrivateKeySigningAlg)
		}
	case ClientAuthNone:
		if c.ClientSecret != "" || c.PrivateKeyPath != "" {
			return fmt.Errorf("config: --client-secret/--private-key-file require --client-auth-method to be set")
		}
	}
	return nil
}

// SigningAlg returns the jose.SignatureAlgorithm for PrivateKeySigningAlg.
// Only meaningful once validate() has confirmed the value is one of
// validSigningAlgs' keys; called after successful Parse.
func (c *Config) SigningAlg() jose.SignatureAlgorithm {
	return validSigningAlgs[c.PrivateKeySigningAlg]
}

// resolvePrivateKey parses PrivateKeyPath into PrivateKey when
// private_key_jwt is selected, so a malformed key file fails fast at
// startup rather than mid-flow.
func (c *Config) resolvePrivateKey() error {
	if c.ClientAuthMethod != ClientAuthPrivateKeyJWT {
		return nil
	}
	b, err := os.ReadFile(c.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("config: read --private-key-file: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return fmt.Errorf("config: --private-key-file %q contains no PEM block", c.PrivateKeyPath)
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return fmt.Errorf("config: --private-key-file %q does not contain a signing key", c.PrivateKeyPath)
		}
		c.PrivateKey = signer
		return nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		c.PrivateKey = key
		return nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		c.PrivateKey = key
		return nil
	}
	return fmt.Errorf("config: --private-key-file %q is not a supported PEM-encoded private key (want PKCS#1, PKCS#8, or EC)", c.PrivateKeyPath)
}

func loadFileConfig(path string) (*fileConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read config file: %w", err)
	}
	var fc fileConfig
	if err := json.Unmarshal(b, &fc); err != nil {
		return nil, fmt.Errorf("config: parse config file: %w", err)
	}
	return &fc, nil
}

func applyFileConfig(cfg *Config, fc *fileConfig) {
	if fc.Issuer != nil {
		cfg.Issuer = *fc.Issuer
	}
	if fc.ClientID != nil {
		cfg.ClientID = *fc.ClientID
	}
	if fc.Scope != nil {
		cfg.Scope = *fc.Scope
	}
	if fc.Audience != nil {
		cfg.Audience = *fc.Audience
	}
	if fc.GrantType != nil {
		cfg.GrantType = GrantType(*fc.GrantType)
	}
	if fc.TokenType != nil {
		cfg.TokenType = TokenType(*fc.TokenType)
	}
	if fc.CacheDir != nil {
		cfg.CacheDir = *fc.CacheDir
	}
	if fc.RedirectPort != nil {
		cfg.RedirectPort = *fc.RedirectPort
	}
	if fc.NonInteractive != nil {
		cfg.NonInteractive = *fc.NonInteractive
	}
	if fc.All != nil {
		cfg.All = *fc.All
	}
	if fc.ClientAuthMethod != nil {
		cfg.ClientAuthMethod = ClientAuthMethod(*fc.ClientAuthMethod)
	}
	if fc.ClientSecret != nil {
		cfg.ClientSecret = *fc.ClientSecret
	}
	if fc.PrivateKeyPath != nil {
		cfg.PrivateKeyPath = *fc.PrivateKeyPath
	}
	if fc.PrivateKeyID != nil {
		cfg.PrivateKeyID = *fc.PrivateKeyID
	}
	if fc.PrivateKeySigningAlg != nil {
		cfg.PrivateKeySigningAlg = *fc.PrivateKeySigningAlg
	}
	if fc.ClientAssertionAudience != nil {
		cfg.ClientAssertionAudience = *fc.ClientAssertionAudience
	}
}
