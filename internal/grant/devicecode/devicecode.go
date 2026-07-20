package devicecode

import (
	"context"
	"flag"

	"github.com/abinnovision/oidc-token-cli/internal/flagbinding"
	"github.com/abinnovision/oidc-token-cli/internal/grant"
	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// DeviceCode implements the RFC 8628 device authorization grant.
type DeviceCode struct{}

var _ grant.Grant = (*DeviceCode)(nil)

func New() *DeviceCode { return &DeviceCode{} }

func (g *DeviceCode) Name() string       { return "device-code" }
func (g *DeviceCode) WireGrant() string  { return "urn:ietf:params:oauth:grant-type:device_code" }
func (g *DeviceCode) Cacheable() bool    { return true }
func (g *DeviceCode) AutoEligible() bool { return true }

func (g *DeviceCode) Viable(env grant.Environment, nonInteractive bool) bool {
	return env.TerminalAttended() && !nonInteractive
}

func (g *DeviceCode) RegisterFlags(_ *flag.FlagSet) {}

func (g *DeviceCode) Fields() []flagbinding.Field { return nil }

func (g *DeviceCode) Finalize(_ map[string]bool) error { return nil }

func (g *DeviceCode) Validate() error                             { return nil }
func (g *DeviceCode) ValidateNotSelected(_ map[string]bool) error { return nil }

func (g *DeviceCode) Bridge() grant.ConfigBridge { return grant.ConfigBridge{} }

func (g *DeviceCode) Execute(ctx context.Context, p grant.Provider, opts grant.ExecOpts) (output.Result, error) {
	return p.DeviceLogin(ctx, opts.Scope, opts.Prompt, opts.ExtraFields)
}
