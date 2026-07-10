package main

import (
	"context"
	"fmt"
	"os"

	"github.com/abinnovision/oidc-token-cli/internal/authflow"
	"github.com/abinnovision/oidc-token-cli/internal/config"
	"github.com/abinnovision/oidc-token-cli/internal/oidc"
	"github.com/abinnovision/oidc-token-cli/internal/runner"
	"github.com/abinnovision/oidc-token-cli/internal/subjecttoken"
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

		ClientAuthMethod:        oidc.ClientAuthMethod(cfg.ClientAuthMethod),
		ClientSecret:            cfg.ClientSecret,
		PrivateKey:              cfg.PrivateKey,
		PrivateKeyID:            cfg.PrivateKeyID,
		PrivateKeySigningAlg:    cfg.SigningAlg(),
		ClientAssertionAudience: cfg.ClientAssertionAudience,
	}
}

// newRealTokenExchangeSource wires the real network-facing tokenExchanger:
// runtime OIDC discovery plus an RFC 8693 token-exchange request, with no
// caching or interactive-login machinery involved.
func newRealTokenExchangeSource(cfg *config.Config) tokenExchanger {
	return &authflow.Source{
		Issuer:   cfg.Issuer,
		ClientID: cfg.ClientID,
		Scope:    cfg.Scope,
		Audience: cfg.Audience,

		ClientAuthMethod:        oidc.ClientAuthMethod(cfg.ClientAuthMethod),
		ClientSecret:            cfg.ClientSecret,
		PrivateKey:              cfg.PrivateKey,
		PrivateKeyID:            cfg.PrivateKeyID,
		PrivateKeySigningAlg:    cfg.SigningAlg(),
		ClientAssertionAudience: cfg.ClientAssertionAudience,
	}
}

// resolveRealSubjectToken resolves cfg's effective subject_token when
// --subject-token-source is set to something other than manual. Currently
// only github-actions is supported; config.validate() already rejects any
// other value, so the default case below is unreachable in practice but
// kept as a defensive fail-fast rather than a silent empty string.
func resolveRealSubjectToken(ctx context.Context, cfg *config.Config) (string, error) {
	switch cfg.SubjectTokenSource {
	case config.SubjectTokenSourceGitHubActions:
		return subjecttoken.FetchGitHubActions(ctx, os.Getenv, cfg.Audience, nil)
	default:
		return "", fmt.Errorf("cmd: unsupported --subject-token-source %q", cfg.SubjectTokenSource)
	}
}
