package main

import (
	"os"

	"github.com/abinnovision/oidc-token-cli/internal/authflow"
	"github.com/abinnovision/oidc-token-cli/internal/config"
	"github.com/abinnovision/oidc-token-cli/internal/runner"
)

// newRealSource wires the real network-facing TokenSource: runtime OIDC
// discovery, environment-driven grant auto-selection, and silent refresh.
func newRealSource(cfg *config.Config) runner.TokenSource {
	return &authflow.Source{
		Issuer:         cfg.Issuer,
		ClientID:       cfg.ClientID,
		Scope:          cfg.Scope,
		Audience:       cfg.Audience,
		GrantType:      authflow.GrantType(cfg.GrantType),
		CallbackPort:   cfg.RedirectPort,
		NonInteractive: cfg.NonInteractive,
		Env:            authflow.DetectEnvironment(),
		OpenBrowser:    authflow.OpenBrowser,
		// Prompt output must never land on stdout, like any other non-token byte.
		Prompt: os.Stderr,
	}
}
