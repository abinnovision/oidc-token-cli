package authcode

import (
	"context"
	"flag"

	"github.com/abinnovision/oidc-token-cli/internal/flagbinding"
	"github.com/abinnovision/oidc-token-cli/internal/grant"
	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// AuthCode implements the authorization_code+PKCE grant (RFC 6749 §4.1,
// RFC 7636).
type AuthCode struct {
	CallbackPort int
}

var _ grant.Grant = (*AuthCode)(nil)

func New() *AuthCode { return &AuthCode{} }

func (g *AuthCode) Name() string       { return "authcode" }
func (g *AuthCode) WireGrant() string  { return "authorization_code" }
func (g *AuthCode) Cacheable() bool    { return true }
func (g *AuthCode) AutoEligible() bool { return true }

func (g *AuthCode) Viable(env grant.Environment, _ bool) bool {
	return env.BrowserAvailable()
}

func (g *AuthCode) RegisterFlags(_ *flag.FlagSet) {}

func (g *AuthCode) Fields() []flagbinding.Field {
	return []flagbinding.Field{
		&flagbinding.IntField{Target: &g.CallbackPort, FlagName: "redirect", JsonKey: "redirect_port", Usage: "fixed loopback callback port for authcode; 0 selects an ephemeral port"},
	}
}

func (g *AuthCode) Finalize(_ map[string]bool) error { return nil }

func (g *AuthCode) Validate() error                             { return nil }
func (g *AuthCode) ValidateNotSelected(_ map[string]bool) error { return nil }

func (g *AuthCode) Bridge() grant.ConfigBridge {
	return grant.ConfigBridge{RedirectPort: g.CallbackPort}
}

func (g *AuthCode) Execute(ctx context.Context, p grant.Provider, opts grant.ExecOpts) (output.Result, error) {
	return p.AuthCodeLogin(ctx, opts.Scope, g.CallbackPort, opts.OpenBrowser, opts.Prompt, opts.HintWriter, opts.ExtraFields)
}
