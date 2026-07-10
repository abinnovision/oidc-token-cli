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
	GrantAuto          GrantType = "auto"
	GrantAuthCode      GrantType = "authcode"
	GrantDeviceCode    GrantType = "device-code"
	GrantTokenExchange GrantType = "token-exchange"
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

// DefaultSubjectTokenType is used for RFC 8693 §3's subject_token_type when
// --subject-token-type isn't set.
const DefaultSubjectTokenType = "urn:ietf:params:oauth:token-type:access_token"

// SubjectTokenSource selects how Config.SubjectToken is obtained.
// SubjectTokenSourceManual (the default) means the caller supplies it
// directly via --subject-token/--subject-token-file/$OIDC_TOKEN_SUBJECT_TOKEN.
// A non-manual value means SubjectToken is intentionally left empty by
// Parse; the caller resolves it from the selected ambient source before
// making the token-exchange request, since Parse/validate must stay free
// of network I/O.
type SubjectTokenSource string

const (
	SubjectTokenSourceManual        SubjectTokenSource = ""
	SubjectTokenSourceGitHubActions SubjectTokenSource = "github-actions"
)

// Config is the fully resolved set of identity/client + behavior knobs.
type Config struct {
	Issuer         string
	ClientID       string
	Scope          string
	Audience       string
	GrantType      GrantType
	TokenType      TokenType
	TokenStoreDir  string
	TokenStore     cache.Backend // auto|keychain|file|none, see cache.Backend
	RedirectPort   int           // 0 = ephemeral loopback port (RFC 8252 default)
	NonInteractive bool
	All            bool // --all: print full JSON document instead of a bare token
	Logout         bool // --logout: clear the cached entry and exit, no login/refresh

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

	// SubjectToken is RFC 8693 §2.1's subject_token, required when
	// GrantType == GrantTokenExchange.
	SubjectToken string
	// SubjectTokenType is RFC 8693 §3's subject_token_type; defaults to
	// DefaultSubjectTokenType.
	SubjectTokenType string
	// RequestedTokenType is RFC 8693 §2.1's optional requested_token_type;
	// omitted from the request entirely when empty.
	RequestedTokenType string
	// Resources are RFC 8693 §2.1's optional, repeatable resource params.
	Resources []string

	// SubjectTokenSource selects how SubjectToken is obtained; see
	// SubjectTokenSource's doc comment.
	SubjectTokenSource SubjectTokenSource
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
	TokenStoreDir  *string `json:"token_store_dir"`
	TokenStore     *string `json:"token_store"`
	RedirectPort   *int    `json:"redirect_port"`
	NonInteractive *bool   `json:"non_interactive"`
	All            *bool   `json:"all"`
	Logout         *bool   `json:"logout"`

	ClientAuthMethod        *string `json:"client_auth_method"`
	ClientSecret            *string `json:"client_secret"`
	PrivateKeyPath          *string `json:"private_key_file"`
	PrivateKeyID            *string `json:"private_key_id"`
	PrivateKeySigningAlg    *string `json:"private_key_alg"`
	ClientAssertionAudience *string `json:"client_assertion_audience"`

	SubjectToken       *string  `json:"subject_token"`
	SubjectTokenType   *string  `json:"subject_token_type"`
	RequestedTokenType *string  `json:"requested_token_type"`
	Resources          []string `json:"resource"`
	SubjectTokenSource *string  `json:"subject_token_source"`
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
	issuer, clientID, scope, audience, grantType, tokenType, tokenStoreDir, tokenStore, nonInteractive, logout  string
	clientAuthMethod, clientSecret, privateKeyPath, privateKeyID, privateKeySigningAlg, clientAssertionAudience string
	subjectToken, subjectTokenType, subjectTokenSource                                                          string
}{
	issuer:         "OIDC_TOKEN_ISSUER",
	clientID:       "OIDC_TOKEN_CLIENT_ID",
	scope:          "OIDC_TOKEN_SCOPE",
	audience:       "OIDC_TOKEN_AUDIENCE",
	grantType:      "OIDC_TOKEN_GRANT_TYPE",
	tokenType:      "OIDC_TOKEN_TOKEN_TYPE",
	tokenStoreDir:  "OIDC_TOKEN_STORE_DIR",
	tokenStore:     "OIDC_TOKEN_STORE",
	nonInteractive: "OIDC_TOKEN_NON_INTERACTIVE",
	logout:         "OIDC_TOKEN_LOGOUT",

	clientAuthMethod:        "OIDC_TOKEN_CLIENT_AUTH_METHOD",
	clientSecret:            "OIDC_TOKEN_CLIENT_SECRET",
	privateKeyPath:          "OIDC_TOKEN_PRIVATE_KEY_FILE",
	privateKeyID:            "OIDC_TOKEN_PRIVATE_KEY_ID",
	privateKeySigningAlg:    "OIDC_TOKEN_PRIVATE_KEY_ALG",
	clientAssertionAudience: "OIDC_TOKEN_CLIENT_ASSERTION_AUDIENCE",

	subjectToken:       "OIDC_TOKEN_SUBJECT_TOKEN",
	subjectTokenType:   "OIDC_TOKEN_SUBJECT_TOKEN_TYPE",
	subjectTokenSource: "OIDC_TOKEN_SUBJECT_TOKEN_SOURCE",
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
		configFile        = fs.String("config", "", "path to an optional JSON config file")
		issuer            = fs.String("issuer", "", "OIDC issuer URL (discovery is fetched from <issuer>/.well-known/openid-configuration)")
		clientID          = fs.String("client-id", "", "OAuth2/OIDC client ID")
		scope             = fs.String("scope", DefaultScope, "space-separated OAuth2 scopes to request")
		audience          = fs.String("audience", "", "expected audience (aud) claim; required whenever the relying party checks it")
		grantType         = fs.String("grant-type", string(GrantAuto), "auto|authcode|device-code")
		tokenType         = fs.String("token-type", string(TokenTypeAccessToken), "access_token|id_token")
		tokenStoreDirFlag = fs.String("token-store-dir", "", "override the token store directory used by the file backend (default: $XDG_CACHE_HOME/oidc-token or ~/.cache/oidc-token)")
		tokenStore        = fs.String("token-store", string(cache.BackendAuto), "auto|keychain|file|none: where tokens are stored; none disables persistence entirely")
		redirectPort      = fs.Int("redirect", 0, "fixed loopback callback port for authcode; 0 selects an ephemeral port")
		nonInteractive    = fs.Bool("non-interactive", false, "fail fast instead of opening a browser or a device-code prompt")
		all               = fs.Bool("all", false, "print a JSON document with every available credential field instead of a bare token")
		logout            = fs.Bool("logout", false, "clear the cached entry for --issuer/--client-id and exit, without logging in or refreshing")

		clientAuthMethod        = fs.String("client-auth-method", string(ClientAuthNone), "client authentication method for the token endpoint: \"\"|client_secret_basic|client_secret_post|private_key_jwt")
		clientSecret            = fs.String("client-secret", "", "client secret for client_secret_basic/client_secret_post (prefer --client-secret-file or $"+envKeys.clientSecret+" over this flag)")
		clientSecretFile        = fs.String("client-secret-file", "", "path to a file containing the client secret (trailing newline trimmed); takes precedence over --client-secret")
		privateKeyFile          = fs.String("private-key-file", "", "PEM file (PKCS#1/PKCS#8/EC) used to sign the private_key_jwt client assertion")
		privateKeyID            = fs.String("private-key-id", "", "optional \"kid\" header on the private_key_jwt client assertion")
		privateKeyAlg           = fs.String("private-key-alg", DefaultPrivateKeySigningAlg, "JWS signing algorithm for private_key_jwt: RS256|RS384|RS512|PS256|PS384|PS512|ES256|ES384|ES512")
		clientAssertionAudience = fs.String("client-assertion-audience", "", "override the \"aud\" claim of the private_key_jwt assertion (default: the discovered token endpoint)")

		subjectToken       = fs.String("subject-token", "", "subject_token for RFC 8693 token exchange (--grant-type=token-exchange); prefer --subject-token-file or $"+envKeys.subjectToken+" over this flag")
		subjectTokenFile   = fs.String("subject-token-file", "", "path to a file containing the subject_token (trailing newline trimmed); takes precedence over --subject-token")
		subjectTokenType   = fs.String("subject-token-type", DefaultSubjectTokenType, "subject_token_type per RFC 8693 §3 (--grant-type=token-exchange)")
		requestedTokenType = fs.String("requested-token-type", "", "optional requested_token_type per RFC 8693 §2.1 (--grant-type=token-exchange); omitted from the request entirely when unset")
		subjectTokenSource = fs.String("subject-token-source", string(SubjectTokenSourceManual), "auto-fetch subject_token from an external source instead of --subject-token: \"\" (manual, default) | github-actions (--grant-type=token-exchange only); mutually exclusive with --subject-token/--subject-token-file/$"+envKeys.subjectToken)
		resources          stringSliceFlag
	)
	fs.Var(&resources, "resource", "target resource URI for RFC 8693 token exchange (--grant-type=token-exchange); repeatable for multiple resource params")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	cfg := &Config{
		Scope:                DefaultScope,
		GrantType:            GrantAuto,
		TokenType:            TokenTypeAccessToken,
		TokenStore:           cache.BackendAuto,
		PrivateKeySigningAlg: DefaultPrivateKeySigningAlg,
		SubjectTokenType:     DefaultSubjectTokenType,
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
	if v := env.get(envKeys.tokenStoreDir); v != "" {
		cfg.TokenStoreDir = v
	}
	if v := env.get(envKeys.tokenStore); v != "" {
		cfg.TokenStore = cache.Backend(v)
	}
	if v := env.get(envKeys.nonInteractive); v != "" {
		cfg.NonInteractive = v == "1" || v == "true"
	}
	if v := env.get(envKeys.logout); v != "" {
		cfg.Logout = v == "1" || v == "true"
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
	if v := env.get(envKeys.subjectToken); v != "" {
		cfg.SubjectToken = v
	}
	if v := env.get(envKeys.subjectTokenType); v != "" {
		cfg.SubjectTokenType = v
	}
	if v := env.get(envKeys.subjectTokenSource); v != "" {
		cfg.SubjectTokenSource = SubjectTokenSource(v)
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
	if explicit["token-store-dir"] {
		cfg.TokenStoreDir = *tokenStoreDirFlag
	}
	if explicit["token-store"] {
		cfg.TokenStore = cache.Backend(*tokenStore)
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
	if explicit["logout"] {
		cfg.Logout = *logout
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
	if explicit["subject-token"] {
		cfg.SubjectToken = *subjectToken
	}
	if explicit["subject-token-type"] {
		cfg.SubjectTokenType = *subjectTokenType
	}
	if explicit["requested-token-type"] {
		cfg.RequestedTokenType = *requestedTokenType
	}
	if explicit["resource"] {
		cfg.Resources = []string(resources)
	}
	if explicit["subject-token-source"] {
		cfg.SubjectTokenSource = SubjectTokenSource(*subjectTokenSource)
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

	// --subject-token-file always takes precedence over --subject-token /
	// OIDC_TOKEN_SUBJECT_TOKEN / the config file's subject_token, mirroring
	// --client-secret-file's precedence above.
	if explicit["subject-token-file"] {
		tok, err := os.ReadFile(*subjectTokenFile)
		if err != nil {
			return nil, fmt.Errorf("config: read --subject-token-file: %w", err)
		}
		cfg.SubjectToken = strings.TrimRight(string(tok), "\n")
	}

	if cfg.TokenStoreDir == "" && cfg.TokenStore != cache.BackendNone {
		dir, err := cache.DefaultDir(env.get)
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		cfg.TokenStoreDir = dir
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
	case GrantAuto, GrantAuthCode, GrantDeviceCode, GrantTokenExchange:
	default:
		return fmt.Errorf("config: invalid --grant-type %q (want auto|authcode|device-code|token-exchange)", c.GrantType)
	}
	switch c.TokenType {
	case TokenTypeAccessToken, TokenTypeIDToken:
	default:
		return fmt.Errorf("config: invalid --token-type %q (want access_token|id_token)", c.TokenType)
	}
	switch c.TokenStore {
	case cache.BackendAuto, cache.BackendKeychain, cache.BackendFile, cache.BackendNone:
	default:
		return fmt.Errorf("config: invalid --token-store %q (want auto|keychain|file|none)", c.TokenStore)
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
	switch c.SubjectTokenSource {
	case SubjectTokenSourceManual, SubjectTokenSourceGitHubActions:
	default:
		return fmt.Errorf("config: invalid --subject-token-source %q (want \"\"|github-actions)", c.SubjectTokenSource)
	}
	if c.GrantType == GrantTokenExchange {
		if c.SubjectTokenSource != SubjectTokenSourceManual && c.SubjectToken != "" {
			return fmt.Errorf("config: --subject-token-source is mutually exclusive with --subject-token/--subject-token-file/$%s", envKeys.subjectToken)
		}
		if c.SubjectTokenSource == SubjectTokenSourceManual && c.SubjectToken == "" {
			return fmt.Errorf("config: --grant-type=token-exchange requires --subject-token, --subject-token-file, $%s, or --subject-token-source", envKeys.subjectToken)
		}
		if c.SubjectTokenType == "" {
			return fmt.Errorf("config: --subject-token-type must not be empty")
		}
	} else if c.SubjectToken != "" || c.RequestedTokenType != "" || len(c.Resources) > 0 || c.SubjectTokenSource != SubjectTokenSourceManual {
		return fmt.Errorf("config: --subject-token/--subject-token-source/--resource/--requested-token-type require --grant-type=token-exchange")
	}
	return nil
}

// stringSliceFlag implements flag.Value for a repeatable string flag (e.g.
// --resource), appending on every Set call.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
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
	if fc.TokenStoreDir != nil {
		cfg.TokenStoreDir = *fc.TokenStoreDir
	}
	if fc.TokenStore != nil {
		cfg.TokenStore = cache.Backend(*fc.TokenStore)
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
	if fc.Logout != nil {
		cfg.Logout = *fc.Logout
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
	if fc.SubjectToken != nil {
		cfg.SubjectToken = *fc.SubjectToken
	}
	if fc.SubjectTokenType != nil {
		cfg.SubjectTokenType = *fc.SubjectTokenType
	}
	if fc.RequestedTokenType != nil {
		cfg.RequestedTokenType = *fc.RequestedTokenType
	}
	if len(fc.Resources) > 0 {
		cfg.Resources = fc.Resources
	}
	if fc.SubjectTokenSource != nil {
		cfg.SubjectTokenSource = SubjectTokenSource(*fc.SubjectTokenSource)
	}
}
