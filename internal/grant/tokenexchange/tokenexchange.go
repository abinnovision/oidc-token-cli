package tokenexchange

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/abinnovision/oidc-token-cli/internal/flagbinding"
	"github.com/abinnovision/oidc-token-cli/internal/grant"
	"github.com/abinnovision/oidc-token-cli/internal/output"
	"github.com/abinnovision/oidc-token-cli/internal/subjecttoken"
)

// Token-type URNs from RFC 8693 used as defaults for subject_token_type.
const (
	defaultSubjectTokenType = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // RFC 8693 token-type URN, not a credential
	envSubjectToken         = "OIDC_TOKEN_SUBJECT_TOKEN"                      //nolint:gosec // env-var name, not a credential
	envSubjectTokenType     = "OIDC_TOKEN_SUBJECT_TOKEN_TYPE"                 //nolint:gosec // env-var name, not a credential
	envSubjectTokenSource   = "OIDC_TOKEN_SUBJECT_TOKEN_SOURCE"               //nolint:gosec // env-var name, not a credential
)

// TokenExchange implements the RFC 8693 token exchange grant.
type TokenExchange struct {
	// Exported resolved values, readable by callers after Finalize.
	SubjectToken       string
	SubjectTokenType   string
	RequestedTokenType string
	Resources          []string
	SubjectTokenSource string
	Audience           string

	// Private flag pointer, populated by RegisterFlags.
	subjectTokenFile *string

	sources []subjecttoken.Source
}

var _ grant.Grant = (*TokenExchange)(nil)

func New(sources []subjecttoken.Source) *TokenExchange { return &TokenExchange{sources: sources} }

func (g *TokenExchange) Name() string { return "token-exchange" }

func (g *TokenExchange) WireGrant() string {
	return "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // RFC 8693 grant-type URN, not a credential
}

func (g *TokenExchange) Cacheable() bool    { return false }
func (g *TokenExchange) AutoEligible() bool { return false }

func (g *TokenExchange) Viable(_ grant.Environment, _ bool) bool { return true }

func (g *TokenExchange) RegisterFlags(fs *flag.FlagSet) {
	g.subjectTokenFile = fs.String("subject-token-file", "", "file containing the subject_token")
}

func (g *TokenExchange) Fields() []flagbinding.Field {
	return []flagbinding.Field{
		&flagbinding.StringField{Target: &g.SubjectToken, FlagName: "subject-token", EnvKey: envSubjectToken, JsonKey: "subject_token", Usage: "subject_token value for token exchange"},
		&flagbinding.StringField{Target: &g.SubjectTokenType, FlagName: "subject-token-type", EnvKey: envSubjectTokenType, JsonKey: "subject_token_type", Usage: "subject_token_type per RFC 8693"},
		&flagbinding.StringField{Target: &g.RequestedTokenType, FlagName: "requested-token-type", JsonKey: "requested_token_type", Usage: "requested_token_type per RFC 8693"},
		&flagbinding.StringField{Target: &g.SubjectTokenSource, FlagName: "subject-token-source", EnvKey: envSubjectTokenSource, JsonKey: "subject_token_source", Usage: "subject_token source: github-actions"},
		&flagbinding.StringSliceField{Target: &g.Resources, FlagName: "resource", JsonKey: "resource", Usage: "target resource URI (repeatable)"},
	}
}

func (g *TokenExchange) Finalize(explicit map[string]bool) error {
	// --subject-token-file always takes precedence over --subject-token /
	// env / file, mirroring --client-secret-file's precedence.
	if explicit["subject-token-file"] {
		tok, err := os.ReadFile(*g.subjectTokenFile)
		if err != nil {
			return fmt.Errorf("config: read --subject-token-file: %w", err)
		}
		g.SubjectToken = strings.TrimRight(string(tok), "\n")
	}

	// Default subject_token_type once the source is known.
	if g.SubjectTokenType == "" {
		if src := subjecttoken.FindSource(g.sources, g.SubjectTokenSource); src != nil {
			g.SubjectTokenType = src.DefaultTokenType()
		} else {
			g.SubjectTokenType = defaultSubjectTokenType
		}
	}

	return nil
}

func (g *TokenExchange) Validate() error {
	if g.SubjectTokenSource != "" && subjecttoken.FindSource(g.sources, g.SubjectTokenSource) == nil {
		return fmt.Errorf("config: invalid --subject-token-source %q (want \"\"|%s)",
			g.SubjectTokenSource, strings.Join(subjecttoken.SourceNames(g.sources), "|"))
	}
	if g.SubjectTokenSource != "" && g.SubjectToken != "" {
		return fmt.Errorf("config: --subject-token-source is mutually exclusive with --subject-token/--subject-token-file/$%s", envSubjectToken)
	}
	if g.SubjectTokenSource == "" && g.SubjectToken == "" {
		return fmt.Errorf("config: --grant-type=token-exchange requires --subject-token, --subject-token-file, $%s, or --subject-token-source", envSubjectToken)
	}
	if g.SubjectTokenType == "" {
		return fmt.Errorf("config: --subject-token-type must not be empty")
	}
	return nil
}

func (g *TokenExchange) ValidateNotSelected(_ map[string]bool) error {
	if g.SubjectToken != "" || g.RequestedTokenType != "" || len(g.Resources) > 0 || g.SubjectTokenSource != "" {
		return fmt.Errorf("config: --subject-token/--subject-token-source/--resource/--requested-token-type require --grant-type=token-exchange")
	}
	return nil
}

func (g *TokenExchange) Bridge() grant.ConfigBridge {
	return grant.ConfigBridge{
		SubjectToken:       g.SubjectToken,
		SubjectTokenType:   g.SubjectTokenType,
		RequestedTokenType: g.RequestedTokenType,
		Resources:          g.Resources,
		SubjectTokenSource: g.SubjectTokenSource,
	}
}

func (g *TokenExchange) Execute(ctx context.Context, p grant.Provider, opts grant.ExecOpts) (output.Result, error) {
	return p.TokenExchange(ctx, opts.Scope, g.SubjectToken, g.SubjectTokenType, g.RequestedTokenType, g.Resources, opts.ExtraFields)
}

// ResolveSubjectToken returns g.SubjectToken as-is if no
// --subject-token-source was configured, otherwise it fetches the
// subject_token from the configured Source.
func (g *TokenExchange) ResolveSubjectToken(ctx context.Context) (string, error) {
	if g.SubjectTokenSource == "" {
		return g.SubjectToken, nil
	}
	src := subjecttoken.FindSource(g.sources, g.SubjectTokenSource)
	if src == nil {
		return "", fmt.Errorf("config: unsupported --subject-token-source %q", g.SubjectTokenSource)
	}
	return src.Fetch(ctx, g.Audience)
}
