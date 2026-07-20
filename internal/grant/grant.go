package grant

import (
	"context"
	"flag"
	"io"
	"net/url"

	"github.com/abinnovision/oidc-token-cli/internal/flagbinding"
	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// Grant is the contract every grant type implements. A Grant is constructed
// once at startup, registers its own flags, validates them after parsing,
// and knows how to execute its token request.
type Grant interface {
	// Name returns the user-facing identifier used with --grant-type
	// (e.g. "authcode", "device-code", "token-exchange").
	Name() string

	// WireGrant returns the RFC grant_type wire value
	// (e.g. "authorization_code", "urn:ietf:params:oauth:grant-type:device_code").
	WireGrant() string

	// RegisterFlags registers this grant's specific flags on fs.
	// Called once during config.Parse, before fs.Parse(args).
	RegisterFlags(fs *flag.FlagSet)

	// Fields returns this grant's table-driven config fields, resolved
	// through the same four-layer precedence stack (default < env < file <
	// explicit flag) as the universal config fields. Grants that don't use
	// the table for a given field manage it manually via RegisterFlags and
	// Finalize.
	Fields() []flagbinding.Field

	// Finalize is called after flag parsing and after all Fields have been
	// resolved, with the set of explicitly-set flag names. Each grant
	// applies any post-resolution logic that doesn't fit the table (e.g.
	// reading a *-file flag's contents, defaulting one field based on
	// another).
	Finalize(explicit map[string]bool) error

	// Bridge returns the grant's resolved values for backward-compatible
	// copy into the Config struct. Grants that own no config-bridged
	// fields return a zero ConfigBridge.
	Bridge() ConfigBridge

	// Validate checks this grant's flags for internal consistency.
	// Called only when this grant is the selected --grant-type.
	Validate() error

	// ValidateNotSelected checks whether the user set flags belonging to
	// this grant while a different grant is selected. Returns an error
	// like "--subject-token requires --grant-type=token-exchange".
	ValidateNotSelected(explicit map[string]bool) error

	// Cacheable reports whether this grant's results should go through
	// the runner's cache/refresh pipeline. Token exchange returns false;
	// authcode and device-code return true.
	Cacheable() bool

	// AutoEligible reports whether this grant participates in
	// --grant-type=auto discovery-driven selection.
	AutoEligible() bool

	// Viable reports whether this grant can execute in the current
	// environment. Only called for grants that are AutoEligible and
	// whose WireGrant the IdP advertises.
	Viable(env Environment, nonInteractive bool) bool

	// Execute performs the token request against the discovered provider.
	Execute(ctx context.Context, p Provider, opts ExecOpts) (output.Result, error)
}

// Environment exposes the runtime capabilities grant selection needs.
type Environment interface {
	BrowserAvailable() bool
	TerminalAttended() bool
}

// Provider is the subset of *oidc.Provider that grants call at execution
// time. Defined as an interface here to avoid a circular dependency
// between internal/grant and internal/oidc, and to keep grants testable
// without a real discovery round-trip.
type Provider interface {
	AuthCodeLogin(ctx context.Context, scope string, port int, openBrowser func(string) error, prompt, hint io.Writer, extraFields url.Values) (output.Result, error)
	DeviceLogin(ctx context.Context, scope string, prompt io.Writer, extraFields url.Values) (output.Result, error)
	TokenExchange(ctx context.Context, scope, subjectToken, subjectTokenType, requestedTokenType string, resources []string, extraFields url.Values) (output.Result, error)
	Refresh(ctx context.Context, scope, refreshToken string) (output.Result, error)
	SupportsGrant(grant string) bool
	SupportsDeviceCode() bool
	AdvertisedGrants() string
}

// ConfigBridge carries grant-resolved values back to the config layer
// for backward compatibility. Each grant populates only the fields it
// owns; zero values are skipped during the copy-back.
type ConfigBridge struct {
	SubjectToken       string
	SubjectTokenType   string
	RequestedTokenType string
	Resources          []string
	SubjectTokenSource string
	RedirectPort       int
}

// ExecOpts carries universal parameters every grant needs at execution
// time. Grant-specific parameters live on each grant's own struct.
type ExecOpts struct {
	Scope       string
	Prompt      io.Writer
	HintWriter  io.Writer
	OpenBrowser func(string) error
	ExtraFields url.Values
}
