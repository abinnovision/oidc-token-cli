package authcode

import (
	"context"
	"flag"

	"github.com/abinnovision/oidc-token-cli/internal/grant"
	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// AuthCode implements the authorization_code+PKCE grant (RFC 6749 §4.1,
// RFC 7636).
type AuthCode struct {
	CallbackPort int

	// Private flag pointer, populated by RegisterFlags.
	redirectPort *int
}

var _ grant.Grant = (*AuthCode)(nil)

func New() *AuthCode { return &AuthCode{} }

func (g *AuthCode) Name() string      { return "authcode" }
func (g *AuthCode) WireGrant() string  { return "authorization_code" }
func (g *AuthCode) Cacheable() bool    { return true }
func (g *AuthCode) AutoEligible() bool { return true }

func (g *AuthCode) Viable(env grant.Environment, _ bool) bool {
	return env.BrowserAvailable()
}

func (g *AuthCode) RegisterFlags(fs *flag.FlagSet) {
	g.redirectPort = fs.Int("redirect", 0, "fixed loopback callback port for authcode; 0 selects an ephemeral port")
}

func (g *AuthCode) Finalize(explicit map[string]bool, _ grant.EnvFunc, fc map[string]any) error {
	// File config.
	if fc != nil {
		if v, ok := fc["redirect_port"]; ok {
			if n, ok := v.(float64); ok {
				g.CallbackPort = int(n)
			}
		}
	}
	// Explicit flag wins.
	if explicit["redirect"] {
		g.CallbackPort = *g.redirectPort
	}
	return nil
}

func (g *AuthCode) Validate() error                             { return nil }
func (g *AuthCode) ValidateNotSelected(_ map[string]bool) error { return nil }

func (g *AuthCode) Bridge() grant.ConfigBridge {
	return grant.ConfigBridge{RedirectPort: g.CallbackPort}
}

func (g *AuthCode) Execute(ctx context.Context, p grant.Provider, opts grant.ExecOpts) (output.Result, error) {
	return p.AuthCodeLogin(ctx, opts.Scope, g.CallbackPort, opts.OpenBrowser, opts.Prompt, opts.HintWriter, opts.ExtraFields)
}
