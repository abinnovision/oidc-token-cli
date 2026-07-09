package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

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
	TokenStore     cache.Backend // auto|keychain|file, see cache.Backend
	RedirectPort   int           // 0 = ephemeral loopback port (RFC 8252 default)
	NonInteractive bool
	All            bool // --all: print full JSON document instead of a bare token
	Logout         bool // --logout: clear the cached entry and exit, no login/refresh
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
	TokenStore     *string `json:"token_store"`
	RedirectPort   *int    `json:"redirect_port"`
	NonInteractive *bool   `json:"non_interactive"`
	All            *bool   `json:"all"`
	Logout         *bool   `json:"logout"`
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
	issuer, clientID, scope, audience, grantType, tokenType, cacheDir, tokenStore, nonInteractive, logout string
}{
	issuer:         "OIDC_TOKEN_ISSUER",
	clientID:       "OIDC_TOKEN_CLIENT_ID",
	scope:          "OIDC_TOKEN_SCOPE",
	audience:       "OIDC_TOKEN_AUDIENCE",
	grantType:      "OIDC_TOKEN_GRANT_TYPE",
	tokenType:      "OIDC_TOKEN_TOKEN_TYPE",
	cacheDir:       "OIDC_TOKEN_CACHE_DIR",
	tokenStore:     "OIDC_TOKEN_STORE",
	nonInteractive: "OIDC_TOKEN_NON_INTERACTIVE",
	logout:         "OIDC_TOKEN_LOGOUT",
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
		fmt.Fprintf(stderr, "Mint and print an OIDC token for a generic public OIDC client.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		configFile     = fs.String("config", "", "path to an optional JSON config file")
		issuer         = fs.String("issuer", "", "OIDC issuer URL (discovery is fetched from <issuer>/.well-known/openid-configuration)")
		clientID       = fs.String("client-id", "", "OAuth2/OIDC public client ID")
		scope          = fs.String("scope", DefaultScope, "space-separated OAuth2 scopes to request")
		audience       = fs.String("audience", "", "expected audience (aud) claim; required whenever the relying party checks it")
		grantType      = fs.String("grant-type", string(GrantAuto), "auto|authcode|device-code")
		tokenType      = fs.String("token-type", string(TokenTypeAccessToken), "access_token|id_token")
		cacheDirFlag   = fs.String("cache-dir", "", "override the token cache directory (default: $XDG_CACHE_HOME/oidc-token or ~/.cache/oidc-token)")
		tokenStore     = fs.String("token-store", string(cache.BackendAuto), "auto|keychain|file: where cached tokens are stored")
		redirectPort   = fs.Int("redirect", 0, "fixed loopback callback port for authcode; 0 selects an ephemeral port")
		nonInteractive = fs.Bool("non-interactive", false, "fail fast instead of opening a browser or a device-code prompt")
		all            = fs.Bool("all", false, "print a JSON document with every available credential field instead of a bare token")
		logout         = fs.Bool("logout", false, "clear the cached entry for --issuer/--client-id and exit, without logging in or refreshing")
	)

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	cfg := &Config{
		Scope:      DefaultScope,
		GrantType:  GrantAuto,
		TokenType:  TokenTypeAccessToken,
		TokenStore: cache.BackendAuto,
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
	if v := env.get(envKeys.tokenStore); v != "" {
		cfg.TokenStore = cache.Backend(v)
	}
	if v := env.get(envKeys.nonInteractive); v != "" {
		cfg.NonInteractive = v == "1" || v == "true"
	}
	if v := env.get(envKeys.logout); v != "" {
		cfg.Logout = v == "1" || v == "true"
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
	switch c.TokenStore {
	case cache.BackendAuto, cache.BackendKeychain, cache.BackendFile:
	default:
		return fmt.Errorf("config: invalid --token-store %q (want auto|keychain|file)", c.TokenStore)
	}
	return nil
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
}
