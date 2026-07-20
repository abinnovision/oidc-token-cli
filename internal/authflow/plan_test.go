package authflow

import (
	"context"
	"crypto"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/abinnovision/oidc-token-cli/internal/oidc"
	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// fakeProvider is a fake grantSource used to unit-test plan() and the
// fallback logic in Source.Login without a real mock HTTP issuer.
type fakeProvider struct {
	supportsAuthcode bool
	supportsDevice   bool

	deviceErr   error
	authcodeErr error
	loginResult output.Result

	deviceCalls   int
	authcodeCalls int

	// lastHint records whether AuthCodeLogin's hint writer was non-nil on
	// its most recent call, and what was written to it.
	lastHintNonNil bool
	lastHintWrite  string

	tokenExchangeErr error
	// lastTokenExchange* record TokenExchange's most recent arguments, for
	// tests asserting Source.TokenExchange delegates them unchanged.
	lastTokenExchangeSubjectToken     string
	lastTokenExchangeSubjectTokenType string
	lastTokenExchangeRequestedType    string
	lastTokenExchangeResources        []string
}

func (f *fakeProvider) SupportsGrant(grant string) bool {
	switch grant {
	case string(grantAuthorizationCode):
		return f.supportsAuthcode
	case string(grantDeviceCodeURN):
		return f.supportsDevice
	}
	return false
}

func (f *fakeProvider) SupportsDeviceCode() bool { return f.supportsDevice }
func (f *fakeProvider) SetAudience(string)       {}
func (f *fakeProvider) AdvertisedGrants() string { return "fake-provider-grants" }
func (f *fakeProvider) SetClientAuth(oidc.ClientAuthMethod, string, crypto.Signer, string, jose.SignatureAlgorithm, string) {
}

func (f *fakeProvider) DeviceLogin(ctx context.Context, scope string, prompt io.Writer, _ url.Values) (output.Result, error) {
	f.deviceCalls++
	if f.deviceErr != nil {
		return output.Result{}, f.deviceErr
	}
	return f.loginResult, nil
}

func (f *fakeProvider) AuthCodeLogin(ctx context.Context, scope string, port int, openBrowser func(string) error, prompt, hint io.Writer, _ url.Values) (output.Result, error) {
	f.authcodeCalls++
	f.lastHintNonNil = hint != nil
	if hint != nil {
		_, _ = hint.Write([]byte("hint-written"))
		f.lastHintWrite = "hint-written"
	} else {
		f.lastHintWrite = ""
	}
	if f.authcodeErr != nil {
		return output.Result{}, f.authcodeErr
	}
	return f.loginResult, nil
}

func (f *fakeProvider) Refresh(ctx context.Context, scope, refreshToken string) (output.Result, error) {
	return f.loginResult, nil
}

func (f *fakeProvider) TokenExchange(ctx context.Context, scope, subjectToken, subjectTokenType, requestedTokenType string, resources []string, _ url.Values) (output.Result, error) {
	f.lastTokenExchangeSubjectToken = subjectToken
	f.lastTokenExchangeSubjectTokenType = subjectTokenType
	f.lastTokenExchangeRequestedType = requestedTokenType
	f.lastTokenExchangeResources = resources
	if f.tokenExchangeErr != nil {
		return output.Result{}, f.tokenExchangeErr
	}
	return f.loginResult, nil
}

// --- plan() negotiation matrix: browser available/unavailable x terminal
// attended/unattended x --non-interactive x IdP-advertised grants. ---

func TestPlan_Auto_BrowserAndTerminal_PrefersAuthcode(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: true}
	order, err := plan(p, GrantAuto, Environment{TTY: true, Display: true}, false)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(order) != 2 || order[0] != grantAuthorizationCode || order[1] != grantDeviceCodeURN {
		t.Fatalf("order = %v, want [authcode, device-code] when both are viable", order)
	}
}

func TestPlan_Auto_NoBrowserNoTerminal_FailsFast(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: true}
	order, err := plan(p, GrantAuto, Environment{TTY: false, Display: false}, false)
	if err == nil {
		t.Fatalf("plan returned order=%v, want a fail-fast error (no browser, no attended terminal)", order)
	}
	if !errors.Is(err, ErrInteractionUnavailable) {
		t.Fatalf("err = %v, want wrapping ErrInteractionUnavailable", err)
	}
	if order != nil {
		t.Fatalf("order = %v, want nil on error", order)
	}
}

func TestPlan_Auto_NoBrowser_TerminalAttended_UsesDeviceCodeOnly(t *testing.T) {
	// No display but a human at the terminal: authcode can't run (no
	// browser to open), device-code can.
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: true}
	order, err := plan(p, GrantAuto, Environment{TTY: true, Display: false}, false)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(order) != 1 || order[0] != grantDeviceCodeURN {
		t.Fatalf("order = %v, want [device-code] only (no browser available)", order)
	}
}

func TestPlan_Auto_BrowserAvailable_NoTTY_UsesAuthcodeOnly(t *testing.T) {
	// The frpc-exec shape: no TTY at all, but a display is present (desktop
	// session). authcode is viable purely on browser availability — it
	// never reads stdin, so TTY-ness is irrelevant to it. device-code is
	// excluded: nobody is at the terminal to read the user_code.
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: true}
	order, err := plan(p, GrantAuto, Environment{TTY: false, Display: true}, false)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(order) != 1 || order[0] != grantAuthorizationCode {
		t.Fatalf("order = %v, want [authcode] only (browser available, terminal unattended)", order)
	}
}

func TestPlan_Auto_NonInteractive_BrowserAvailable_StillAttemptsAuthcode(t *testing.T) {
	// --non-interactive means "terminal unattended", not "never log in": a
	// browser-based login is still permitted when a display exists.
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: true}
	order, err := plan(p, GrantAuto, Environment{TTY: true, Display: true}, true)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(order) != 1 || order[0] != grantAuthorizationCode {
		t.Fatalf("order = %v, want [authcode] only: --non-interactive excludes device-code but not authcode", order)
	}
}

func TestPlan_Auto_NonInteractive_NoBrowser_FailsFast(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: true}
	order, err := plan(p, GrantAuto, Environment{TTY: true, Display: false}, true)
	if err == nil {
		t.Fatalf("plan returned order=%v, want a fail-fast error: no browser, and --non-interactive excludes device-code", order)
	}
	if !errors.Is(err, ErrInteractionUnavailable) {
		t.Fatalf("err = %v, want wrapping ErrInteractionUnavailable", err)
	}
}

func TestPlan_Auto_DeviceOnlyAdvertised_NoBrowser_UsesDevice(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: false, supportsDevice: true}
	order, err := plan(p, GrantAuto, Environment{TTY: true, Display: false}, false)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(order) != 1 || order[0] != grantDeviceCodeURN {
		t.Fatalf("order = %v, want [device-code]", order)
	}
}

func TestPlan_Auto_AuthcodeOnlyAdvertised_NonInteractive_BrowserAvailable_UsesAuthcode(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: false}
	order, err := plan(p, GrantAuto, Environment{TTY: false, Display: true}, true)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(order) != 1 || order[0] != grantAuthorizationCode {
		t.Fatalf("order = %v, want [authcode]", order)
	}
}

func TestPlan_Auto_NeitherPossible_ClearError(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: false, supportsDevice: false}
	_, err := plan(p, GrantAuto, Environment{TTY: true, Display: true}, false)
	if err == nil {
		t.Fatal("expected an error when neither grant is possible")
	}
}

func TestPlan_ExplicitAuthCode_NoBrowser_FailsFast(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: false}
	_, err := plan(p, GrantAuthCode, Environment{TTY: true, Display: false}, false)
	if !errors.Is(err, ErrInteractionUnavailable) {
		t.Fatalf("err = %v, want wrapping ErrInteractionUnavailable for an explicit authcode request with no browser", err)
	}
}

func TestPlan_ExplicitAuthCode_NoTTY_BrowserAvailable_Succeeds(t *testing.T) {
	// authcode never needs a TTY — only a browser.
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: false}
	order, err := plan(p, GrantAuthCode, Environment{TTY: false, Display: true}, false)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(order) != 1 || order[0] != grantAuthorizationCode {
		t.Fatalf("order = %v, want [authcode]", order)
	}
}

func TestPlan_ExplicitAuthCode_NonInteractive_BrowserAvailable_Succeeds(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: false}
	order, err := plan(p, GrantAuthCode, Environment{TTY: true, Display: true}, true)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(order) != 1 || order[0] != grantAuthorizationCode {
		t.Fatalf("order = %v, want [authcode]: --non-interactive doesn't block authcode when a browser is available", order)
	}
}

func TestPlan_ExplicitAuthCode_NotSupported_Error(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: false, supportsDevice: true}
	_, err := plan(p, GrantAuthCode, Environment{}, false)
	if err == nil {
		t.Fatal("expected an error when authcode is explicitly requested but unsupported")
	}
}

func TestPlan_ExplicitDeviceCode_NotSupported_Error(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: false}
	_, err := plan(p, GrantDeviceCode, Environment{}, false)
	if err == nil {
		t.Fatal("expected an error when device-code is explicitly requested but unsupported")
	}
}

func TestPlan_ExplicitDeviceCode_NonInteractive_FailsFast(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: true}
	_, err := plan(p, GrantDeviceCode, Environment{TTY: true, Display: true}, true)
	if !errors.Is(err, ErrInteractionUnavailable) {
		t.Fatalf("err = %v, want wrapping ErrInteractionUnavailable: --non-interactive rules out device-code even when attended", err)
	}
}

func TestPlan_ExplicitDeviceCode_NoTTY_FailsFast(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: true}
	_, err := plan(p, GrantDeviceCode, Environment{TTY: false, Display: true}, false)
	if !errors.Is(err, ErrInteractionUnavailable) {
		t.Fatalf("err = %v, want wrapping ErrInteractionUnavailable: device-code needs an attended terminal", err)
	}
}

func TestPlan_NeverExceedsTwoGrants(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: true}
	envs := []Environment{
		{TTY: true, Display: true},
		{TTY: false, Display: false},
		{TTY: true, Display: false},
		{TTY: false, Display: true},
	}
	for _, env := range envs {
		order, err := plan(p, GrantAuto, env, false)
		if err != nil {
			continue
		}
		if len(order) > maxInteractiveAttempts {
			t.Fatalf("order = %v exceeds maxInteractiveAttempts=%d", order, maxInteractiveAttempts)
		}
		seen := map[Grant]bool{}
		for _, g := range order {
			if seen[g] {
				t.Fatalf("order = %v contains a duplicate grant (no cycles allowed)", order)
			}
			seen[g] = true
		}
	}
}

func TestPlan_NoViableGrant_DiagnosticEnumeratesNegotiation(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: true}
	_, err := plan(p, GrantAuto, Environment{TTY: false, Display: false}, true)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, want := range []string{
		"fake-provider-grants",
		"browser: unavailable (no $DISPLAY/$WAYLAND_DISPLAY)",
		"terminal: unattended (--non-interactive)",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error message = %q, want it to contain %q", msg, want)
		}
	}
}

func TestPlan_NoViableGrant_DiagnosticReflectsNoTTYNotNonInteractive(t *testing.T) {
	p := &fakeProvider{supportsAuthcode: true, supportsDevice: true}
	_, err := plan(p, GrantAuto, Environment{TTY: false, Display: false}, false)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "terminal: unattended (no TTY)") {
		t.Fatalf("error message = %q, want it to distinguish no-TTY from --non-interactive", err.Error())
	}
}
