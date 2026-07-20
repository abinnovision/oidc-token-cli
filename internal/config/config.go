package config

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/abinnovision/oidc-token-cli/internal/cache"
	"github.com/abinnovision/oidc-token-cli/internal/flagbinding"
	"github.com/abinnovision/oidc-token-cli/internal/grant"
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

// OutputFormat selects how the final result is written to stdout.
type OutputFormat string

const (
	OutputFormatToken          OutputFormat = "token"
	OutputFormatJSON           OutputFormat = "json"
	OutputFormatExecCredential OutputFormat = "exec-credential" //nolint:gosec // G101 false positive: k8s output-format name, not a credential
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
// --subject-token-type isn't set and no source-specific default applies.
const DefaultSubjectTokenType = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // RFC 8693 token-type URN, not a credential

// DefaultSubjectTokenTypeGitHubActions is the subject_token_type default when
// --subject-token-source=github-actions and --subject-token-type isn't set.
// The GitHub Actions OIDC endpoint issues an ID token, so the RFC 8693 type
// must be id_token rather than the generic access_token default.
const DefaultSubjectTokenTypeGitHubActions = "urn:ietf:params:oauth:token-type:id_token" //nolint:gosec // RFC 8693 token-type URN, not a credential

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
	Format         OutputFormat // --format: token|json|exec-credential, see OutputFormat
	All            bool         // --all: print full JSON document instead of a bare token (deprecated: use --format=json)
	Logout         bool         // --logout: clear the cached entry and exit, no login/refresh
	ExtraFields    url.Values   // --extra key=value pairs forwarded to the token endpoint

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
	// GrantType == GrantTokenExchange. Populated from the token-exchange
	// grant's Bridge after Finalize.
	SubjectToken string
	// SubjectTokenType is RFC 8693 §3's subject_token_type; defaults to
	// DefaultSubjectTokenType, or DefaultSubjectTokenTypeGitHubActions when
	// SubjectTokenSource is SubjectTokenSourceGitHubActions. Populated from
	// the token-exchange grant's Bridge after Finalize.
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

// Parse builds a Config from, in ascending priority: defaults, environment
// variables, an optional --config JSON file, then explicitly-set flags.
// Flags always win; a flag the caller didn't pass on the command line never
// overrides a value from a lower-priority source.
//
// Each grant in grants registers its own flags, finalizes its state after
// parsing, and validates itself. Parse orchestrates this lifecycle and
// copies grant-resolved values back into Config via Bridge for backward
// compatibility.
func Parse(args []string, stderr io.Writer, env Env, grants []grant.Grant) (*Config, error) {
	fs := flag.NewFlagSet("oidc-token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: oidc-token [flags]\n\n")
		fmt.Fprintf(stderr, "Mint and print an OIDC token for a public or confidential OIDC client.\n\n")
		printGroupedUsage(stderr, fs)
	}

	cfg := &Config{
		Scope:                DefaultScope,
		GrantType:            GrantAuto,
		TokenType:            TokenTypeAccessToken,
		TokenStore:           cache.BackendAuto,
		PrivateKeySigningAlg: DefaultPrivateKeySigningAlg,
	}

	// Intermediate strings for custom-type fields, resolved after the loop.
	var (
		grantTypeStr  = string(GrantAuto)
		tokenTypeStr  = string(TokenTypeAccessToken)
		tokenStoreStr = string(cache.BackendAuto)
		formatStr     = string(OutputFormatToken)
		clientAuthStr string
	)

	// The binding table: one entry per universal config field, four layers,
	// zero per-field boilerplate.
	fields := []flagbinding.Field{
		&flagbinding.StringField{Target: &cfg.Issuer, FlagName: "issuer", EnvKey: "OIDC_TOKEN_ISSUER", JsonKey: "issuer", Usage: "OIDC issuer URL"},
		&flagbinding.StringField{Target: &cfg.ClientID, FlagName: "client-id", EnvKey: "OIDC_TOKEN_CLIENT_ID", JsonKey: "client_id", Usage: "OAuth2 client ID"},
		&flagbinding.StringField{Target: &cfg.Scope, FlagName: "scope", EnvKey: "OIDC_TOKEN_SCOPE", JsonKey: "scope", Usage: "space-separated OAuth2 scopes", Def: DefaultScope},
		&flagbinding.StringField{Target: &cfg.Audience, FlagName: "audience", EnvKey: "OIDC_TOKEN_AUDIENCE", JsonKey: "audience", Usage: "audience (aud) claim for the token request"},
		&flagbinding.StringField{Target: &grantTypeStr, FlagName: "grant-type", EnvKey: "OIDC_TOKEN_GRANT_TYPE", JsonKey: "grant_type", Usage: "auto|authcode|device-code|token-exchange", Def: string(GrantAuto)},
		&flagbinding.StringField{Target: &tokenTypeStr, FlagName: "token-type", EnvKey: "OIDC_TOKEN_TOKEN_TYPE", JsonKey: "token_type", Usage: "access_token|id_token", Def: string(TokenTypeAccessToken)},
		&flagbinding.StringField{Target: &cfg.TokenStoreDir, FlagName: "token-store-dir", EnvKey: "OIDC_TOKEN_STORE_DIR", JsonKey: "token_store_dir", Usage: "token store directory for the file backend"},
		&flagbinding.StringField{Target: &tokenStoreStr, FlagName: "token-store", EnvKey: "OIDC_TOKEN_STORE", JsonKey: "token_store", Usage: "auto|keychain|file|none", Def: string(cache.BackendAuto)},
		&flagbinding.BoolField{Target: &cfg.NonInteractive, FlagName: "non-interactive", EnvKey: "OIDC_TOKEN_NON_INTERACTIVE", JsonKey: "non_interactive", Usage: "disable browser and device-code prompts"},
		&flagbinding.StringField{Target: &formatStr, FlagName: "format", EnvKey: "OIDC_TOKEN_FORMAT", JsonKey: "format", Usage: "token|json|exec-credential", Def: string(OutputFormatToken)},
		&flagbinding.BoolField{Target: &cfg.All, FlagName: "all", JsonKey: "all", Usage: "print full JSON token response (deprecated: use --format=json)"},
		&flagbinding.BoolField{Target: &cfg.Logout, FlagName: "logout", EnvKey: "OIDC_TOKEN_LOGOUT", JsonKey: "logout", Usage: "clear cached tokens and exit"},
		&flagbinding.StringField{Target: &clientAuthStr, FlagName: "client-auth-method", EnvKey: "OIDC_TOKEN_CLIENT_AUTH_METHOD", JsonKey: "client_auth_method", Usage: "client_secret_basic|client_secret_post|private_key_jwt"},
		&flagbinding.StringField{Target: &cfg.ClientSecret, FlagName: "client-secret", EnvKey: "OIDC_TOKEN_CLIENT_SECRET", JsonKey: "client_secret", Usage: "client secret for client_secret_basic or client_secret_post"},
		&flagbinding.StringField{Target: &cfg.PrivateKeyPath, FlagName: "private-key-file", EnvKey: "OIDC_TOKEN_PRIVATE_KEY_FILE", JsonKey: "private_key_file", Usage: "PEM private key file for private_key_jwt"},
		&flagbinding.StringField{Target: &cfg.PrivateKeyID, FlagName: "private-key-id", EnvKey: "OIDC_TOKEN_PRIVATE_KEY_ID", JsonKey: "private_key_id", Usage: "kid header for the private_key_jwt assertion"},
		&flagbinding.StringField{Target: &cfg.PrivateKeySigningAlg, FlagName: "private-key-alg", EnvKey: "OIDC_TOKEN_PRIVATE_KEY_ALG", JsonKey: "private_key_alg", Usage: "signing algorithm for private_key_jwt", Def: DefaultPrivateKeySigningAlg},
		&flagbinding.StringField{Target: &cfg.ClientAssertionAudience, FlagName: "client-assertion-audience", EnvKey: "OIDC_TOKEN_CLIENT_ASSERTION_AUDIENCE", JsonKey: "client_assertion_audience", Usage: "aud claim override for private_key_jwt"},
	}

	// Collect grant-specific table-driven fields alongside the universal
	// ones, so they share the same registration and resolution loops.
	for _, g := range grants {
		fields = append(fields, g.Fields()...)
	}

	// Special flags that don't fit the table.
	configFile := fs.String("config", "", "path to a JSON config file")
	clientSecretFile := fs.String("client-secret-file", "", "file containing the client secret")
	var extras extraFieldsFlag

	// 1. Register table-driven flags, grant flags, and special flags.
	for _, f := range fields {
		f.Register(fs)
	}
	for _, g := range grants {
		g.RegisterFlags(fs)
	}
	fs.Var(&extras, "extra", "extra key=value pair for the token endpoint (repeatable)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// 2. Parse config file once as raw map (used by both table and grants).
	var rawFC map[string]any
	if *configFile != "" {
		b, err := os.ReadFile(*configFile) //nolint:gosec // path is a user-supplied CLI flag
		if err != nil {
			return nil, fmt.Errorf("config: read config file: %w", err)
		}
		if err := json.Unmarshal(b, &rawFC); err != nil {
			return nil, fmt.Errorf("config: parse config file: %w", err)
		}
	}

	// 3. Resolve each field through the precedence stack: env < file < flag.
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	for _, f := range fields {
		f.ApplyEnv(env.get)
		f.ApplyFile(rawFC)
		f.ApplyFlag(explicit)
	}

	// 4. Copy intermediate strings to typed config fields.
	cfg.GrantType = GrantType(grantTypeStr)
	cfg.TokenType = TokenType(tokenTypeStr)
	cfg.TokenStore = cache.Backend(tokenStoreStr)
	cfg.ClientAuthMethod = ClientAuthMethod(clientAuthStr)
	cfg.Format = OutputFormat(formatStr)
	if !explicit["format"] && cfg.All {
		cfg.Format = OutputFormatJSON
	}

	// 5. Special-case overrides not covered by the table.
	if explicit["extra"] {
		cfg.ExtraFields = url.Values(extras)
	}
	if rawFC != nil {
		if extraMap, ok := rawFC["extra"].(map[string]any); ok {
			if cfg.ExtraFields == nil {
				cfg.ExtraFields = url.Values{}
			}
			for k, v := range extraMap {
				if s, ok := v.(string); ok {
					cfg.ExtraFields.Set(k, s)
				}
			}
		}
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

	if cfg.TokenStoreDir == "" && cfg.TokenStore != cache.BackendNone {
		dir, err := cache.DefaultDir(env.get)
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		cfg.TokenStoreDir = dir
	}

	// 6. Let each grant finalize its own flag state with the full layering
	// context (explicit flags, env-var lookup, raw file config).
	for _, g := range grants {
		if err := g.Finalize(explicit); err != nil {
			return nil, err
		}
	}

	// 7. Validate universal config fields.
	if err := cfg.validate(grants); err != nil {
		return nil, err
	}

	// 8. Validate grants: the selected grant checks internal consistency;
	// non-selected grants check that their flags weren't erroneously set.
	for _, g := range grants {
		if g.Name() == string(cfg.GrantType) {
			if err := g.Validate(); err != nil {
				return nil, err
			}
		} else {
			if err := g.ValidateNotSelected(explicit); err != nil {
				return nil, err
			}
		}
	}

	// 9. Copy grant-resolved values back into Config for backward compat.
	for _, g := range grants {
		b := g.Bridge()
		if b.SubjectToken != "" {
			cfg.SubjectToken = b.SubjectToken
		}
		if b.SubjectTokenType != "" {
			cfg.SubjectTokenType = b.SubjectTokenType
		}
		if b.RequestedTokenType != "" {
			cfg.RequestedTokenType = b.RequestedTokenType
		}
		if len(b.Resources) > 0 {
			cfg.Resources = b.Resources
		}
		if b.SubjectTokenSource != "" {
			cfg.SubjectTokenSource = SubjectTokenSource(b.SubjectTokenSource)
		}
		if b.RedirectPort != 0 {
			cfg.RedirectPort = b.RedirectPort
		}
	}

	if err := cfg.resolvePrivateKey(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate(grants []grant.Grant) error {
	if c.Issuer == "" {
		return fmt.Errorf("config: --issuer is required")
	}
	if c.ClientID == "" {
		return fmt.Errorf("config: --client-id is required")
	}
	// Validate --grant-type against the registered grants.
	if c.GrantType != GrantAuto {
		valid := false
		for _, g := range grants {
			if g.Name() == string(c.GrantType) {
				valid = true
				break
			}
		}
		if !valid {
			names := make([]string, 0, len(grants)+1)
			names = append(names, "auto")
			for _, g := range grants {
				names = append(names, g.Name())
			}
			return fmt.Errorf("config: invalid --grant-type %q (want %s)", c.GrantType, strings.Join(names, "|"))
		}
	}
	switch c.TokenType {
	case TokenTypeAccessToken, TokenTypeIDToken:
	default:
		return fmt.Errorf("config: invalid --token-type %q (want access_token|id_token)", c.TokenType)
	}
	switch c.Format {
	case OutputFormatToken, OutputFormatJSON, OutputFormatExecCredential:
	default:
		return fmt.Errorf("config: invalid --format %q (want token|json|exec-credential)", c.Format)
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

// extraFieldsFlag implements flag.Value for --extra key=value, a repeatable
// flag that accumulates into url.Values.
type extraFieldsFlag url.Values

func (f *extraFieldsFlag) String() string { return "" }

func (f *extraFieldsFlag) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("--extra value %q must be key=value", v)
	}
	if *f == nil {
		*f = extraFieldsFlag(url.Values{})
	}
	url.Values(*f).Add(k, val)
	return nil
}
