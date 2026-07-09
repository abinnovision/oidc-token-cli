package authflow

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"sync"

	jose "github.com/go-jose/go-jose/v4"
	upstream "golang.org/x/oauth2"

	"github.com/abinnovision/oidc-token-cli/internal/oidc"
	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// GrantType selects which OAuth2 grant(s) are eligible for interactive
// login. Duplicated from config.GrantType/oidc.GrantType deliberately (see
// oidc.Source's doc comment, prior to its removal in Phase 3): each layer
// stays independently typed, and cmd/oidc-token converts between them.
type GrantType string

const (
	GrantAuto       GrantType = "auto"
	GrantAuthCode   GrantType = "authcode"
	GrantDeviceCode GrantType = "device-code"
)

// Grant identifies a single OAuth2 grant by its wire name, as used with
// grantSource.SupportsGrant.
type Grant string

const (
	grantAuthorizationCode Grant = "authorization_code"
	grantDeviceCodeURN     Grant = "urn:ietf:params:oauth:grant-type:device_code"
)

// maxInteractiveAttempts bounds total interactive attempts across a single
// Login call: each grant is tried at most once, no authcode->device->
// authcode cycles, per the plan's bounded-fallback guardrail.
const maxInteractiveAttempts = 2

// ErrInteractionUnavailable is returned when no grant plan() considered is
// actually viable in the current environment: authcode needs a browser,
// device-code needs an attended terminal (and not --non-interactive), and
// neither condition holds. Every returned error wraps this sentinel with
// %w plus a diagnostic built from the actual negotiation (see
// negotiationDiagnostic), so callers can both errors.Is against a stable
// value and print a human-readable reason.
var ErrInteractionUnavailable = errors.New("authflow: no viable login method")

// grantSource is the subset of *oidc.Provider that grant selection needs.
// It exists so plan()/Source.Login's fallback logic can be unit-tested
// against a fake, without a real mock HTTP issuer.
type grantSource interface {
	SupportsGrant(grant string) bool
	SupportsDeviceCode() bool
	SetAudience(audience string)
	// AdvertisedGrants describes, for error messages, which grants the
	// issuer appears to support — never hardcode a grant name in an error
	// message when this is available instead.
	AdvertisedGrants() string
	DeviceLogin(ctx context.Context, scope string, prompt io.Writer) (output.Result, error)
	AuthCodeLogin(ctx context.Context, scope string, port int, openBrowser func(string) error, prompt, hint io.Writer) (output.Result, error)
	Refresh(ctx context.Context, scope, refreshToken string) (output.Result, error)
	SetClientAuth(method oidc.ClientAuthMethod, secret string, signer crypto.Signer, keyID string, alg jose.SignatureAlgorithm, audience string)
}

// negotiationDiagnostic renders the actual negotiation state — what the
// IdP advertises, whether a browser could be launched, whether a human is
// at the terminal — into the fail-fast error message. Every reason is
// derived from a real check, never hardcoded, so the message always
// reflects why *this* invocation failed.
func negotiationDiagnostic(p grantSource, env Environment, nonInteractive bool) string {
	browserReason := "available"
	if !env.BrowserAvailable() {
		browserReason = "unavailable (no $DISPLAY/$WAYLAND_DISPLAY)"
	}
	terminalReason := "attended"
	switch {
	case nonInteractive:
		terminalReason = "unattended (--non-interactive)"
	case !env.TerminalAttended():
		terminalReason = "unattended (no TTY)"
	}
	return fmt.Sprintf("IdP offers [%s]; browser: %s; terminal: %s", p.AdvertisedGrants(), browserReason, terminalReason)
}

// plan returns the ordered list of grants Login should attempt: discovery
// decides what's *possible*, environment (plus --non-interactive) decides
// which of the possible grants are *viable*. The list never exceeds 2
// entries (each grant appears at most once), matching the bounded-fallback
// guardrail directly in its construction.
//
// Viability is per-grant, not a single blanket "interactive" flag:
// authcode only ever needs a browser (it never reads stdin — the terminal
// just waits for the loopback callback), so it's viable under
// --non-interactive whenever a browser is available. device-code needs a
// human to read the user_code off stderr, so it requires an attended
// terminal AND is excluded outright by --non-interactive.
func plan(p grantSource, grantType GrantType, env Environment, nonInteractive bool) ([]Grant, error) {
	authcodeAdvertised := p.SupportsGrant(string(grantAuthorizationCode))
	deviceAdvertised := p.SupportsDeviceCode() && p.SupportsGrant(string(grantDeviceCodeURN))

	authcodeViable := authcodeAdvertised && env.BrowserAvailable()
	deviceViable := deviceAdvertised && env.TerminalAttended() && !nonInteractive

	switch grantType {
	case GrantAuthCode:
		if !authcodeAdvertised {
			return nil, fmt.Errorf("authflow: issuer does not support the authorization_code grant (issuer advertises: %s)", p.AdvertisedGrants())
		}
		if !authcodeViable {
			return nil, fmt.Errorf("%w: --grant-type=authcode requires a browser; %s", ErrInteractionUnavailable, negotiationDiagnostic(p, env, nonInteractive))
		}
		return []Grant{grantAuthorizationCode}, nil

	case GrantDeviceCode:
		if !deviceAdvertised {
			return nil, fmt.Errorf("authflow: issuer does not support the device-code grant (issuer advertises: %s)", p.AdvertisedGrants())
		}
		if !deviceViable {
			return nil, fmt.Errorf("%w: --grant-type=device-code requires an attended terminal; %s", ErrInteractionUnavailable, negotiationDiagnostic(p, env, nonInteractive))
		}
		return []Grant{grantDeviceCodeURN}, nil

	case GrantAuto, "":
		if !authcodeAdvertised && !deviceAdvertised {
			return nil, fmt.Errorf("authflow: issuer advertises neither authorization_code nor device-code as usable grants (issuer advertises: %s)", p.AdvertisedGrants())
		}
		// Bounded-fallback order is fixed: authcode (the more universally
		// supported grant per OIDC Discovery §3's default) first, then
		// device-code as a fallback — never the reverse, and never a cycle
		// back to a grant already attempted.
		var order []Grant
		if authcodeViable {
			order = append(order, grantAuthorizationCode)
		}
		if deviceViable {
			order = append(order, grantDeviceCodeURN)
		}
		if len(order) == 0 {
			return nil, fmt.Errorf("%w: %s", ErrInteractionUnavailable, negotiationDiagnostic(p, env, nonInteractive))
		}
		return order, nil

	default:
		return nil, fmt.Errorf("authflow: unknown grant type %q", grantType)
	}
}

// isPerClientRejection reports whether err indicates the specific client
// is not permitted to use the grant it just attempted — as opposed to a
// transient/network/timeout/user-declined/expired-code failure — per the
// plan's guardrail: "each grant attempted AT MOST ONCE... where the IdP
// signals unauthorized_client/invalid_grant". Discovery reports issuer
// capability, not per-client permission, so this is the only reliable
// fallback trigger.
//
// The two error sources are deliberately treated differently:
//
//   - *oidc.AuthorizationError comes from the authorization endpoint,
//     before any login happened. Both unauthorized_client and invalid_grant
//     there mean the client itself isn't permitted for this grant — always
//     a fallback trigger.
//   - *upstream.RetrieveError comes from the TOKEN endpoint, after the
//     user already completed login. unauthorized_client there still means
//     "this client can't use this grant" (fallback is warranted). But
//     invalid_grant at the token endpoint usually means the authorization
//     code expired, was already used, or the PKCE verifier didn't match —
//     none of which a second interactive attempt on a *different* grant
//     would fix, and forcing the user through a second browser/device
//     flow for an error that's really "your code just expired" is a bad
//     failure mode. So invalid_grant from the token endpoint is surfaced
//     directly instead of triggering fallback.
func isPerClientRejection(err error) bool {
	var re *upstream.RetrieveError
	if errors.As(err, &re) {
		return re.ErrorCode == "unauthorized_client"
	}
	var ae *oidc.AuthorizationError
	if errors.As(err, &ae) {
		switch ae.Code {
		case "unauthorized_client", "invalid_grant":
			return true
		}
	}
	return false
}

// Source is the full runner.TokenSource implementation: runtime discovery,
// discovery+environment-driven grant auto-selection with bounded per-
// client fallback, and silent refresh. It satisfies runner.TokenSource
// structurally — this package never imports internal/runner.
type Source struct {
	Issuer         string
	ClientID       string
	Scope          string
	Audience       string
	GrantType      GrantType
	CallbackPort   int // 0 = ephemeral loopback port; fixed port otherwise
	NonInteractive bool
	Env            Environment
	// OpenBrowser is invoked with the authorization URL during authcode
	// login; nil skips opening (the URL is still printed to Prompt).
	OpenBrowser func(url string) error
	// Prompt receives device-code/authcode verification URLs and fallback
	// warnings. Must never be stdout.
	Prompt io.Writer

	// Client-authentication configuration for the token endpoint.
	// ClientAuthMethod == "" (oidc.ClientAuthNone) is a public client,
	// this tool's original and still default behavior.
	ClientAuthMethod        oidc.ClientAuthMethod
	ClientSecret            string
	PrivateKey              crypto.Signer
	PrivateKeyID            string
	PrivateKeySigningAlg    jose.SignatureAlgorithm
	ClientAssertionAudience string

	mu       sync.Mutex
	provider grantSource
	// discoverFunc is overridden in tests to inject a fake grantSource
	// without a real network round-trip. Defaults to oidc.Discover.
	discoverFunc func(ctx context.Context, issuer, clientID string) (grantSource, error)
}

func (s *Source) discover(ctx context.Context) (grantSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.provider != nil {
		return s.provider, nil
	}
	discover := s.discoverFunc
	if discover == nil {
		discover = defaultDiscover
	}
	p, err := discover(ctx, s.Issuer, s.ClientID)
	if err != nil {
		return nil, err
	}
	p.SetAudience(s.Audience)
	p.SetClientAuth(s.ClientAuthMethod, s.ClientSecret, s.PrivateKey, s.PrivateKeyID, s.PrivateKeySigningAlg, s.ClientAssertionAudience)
	s.provider = p
	return p, nil
}

func defaultDiscover(ctx context.Context, issuer, clientID string) (grantSource, error) {
	p, err := oidc.Discover(ctx, issuer, clientID)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Refresh implements runner.TokenSource.
func (s *Source) Refresh(ctx context.Context, refreshToken string) (output.Result, error) {
	p, err := s.discover(ctx)
	if err != nil {
		return output.Result{}, err
	}
	return p.Refresh(ctx, s.Scope, refreshToken)
}

// Login implements runner.TokenSource: selects a grant order via plan(),
// then attempts each in turn, falling back only on a per-client rejection,
// up to maxInteractiveAttempts total.
func (s *Source) Login(ctx context.Context) (output.Result, error) {
	p, err := s.discover(ctx)
	if err != nil {
		return output.Result{}, err
	}

	order, err := plan(p, s.GrantType, s.Env, s.NonInteractive)
	if err != nil {
		return output.Result{}, err
	}
	if len(order) > maxInteractiveAttempts {
		order = order[:maxInteractiveAttempts]
	}

	var lastErr error
	for i, grant := range order {
		res, err := s.attempt(ctx, p, grant)
		if err == nil {
			return res, nil
		}
		lastErr = err
		last := i == len(order)-1
		if last || !isPerClientRejection(err) {
			return output.Result{}, err
		}
		if s.Prompt != nil {
			fmt.Fprintf(s.Prompt, "warning: %s grant rejected (%v); falling back to the other advertised grant\n", grant, err)
		}
	}
	return output.Result{}, lastErr
}

func (s *Source) attempt(ctx context.Context, p grantSource, grant Grant) (output.Result, error) {
	switch grant {
	case grantDeviceCodeURN:
		return p.DeviceLogin(ctx, s.Scope, s.Prompt)
	case grantAuthorizationCode:
		return p.AuthCodeLogin(ctx, s.Scope, s.CallbackPort, s.OpenBrowser, s.Prompt, s.hintWriter())
	default:
		return output.Result{}, fmt.Errorf("authflow: unknown grant %q", grant)
	}
}

// hintWriter is where AuthCodeLogin's optional "visit this URL" fallback
// text goes: nil when the terminal is unattended, so it never lands in a
// log nobody is reading (e.g. frpc's captured exec output) — unlike
// s.Prompt, which still receives required warnings regardless.
func (s *Source) hintWriter() io.Writer {
	if !s.Env.TerminalAttended() {
		return nil
	}
	return s.Prompt
}
