package tokenexchange

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/abinnovision/oidc-token-cli/internal/grant"
	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// Token-type URNs from RFC 8693 used as defaults for subject_token_type.
const (
	defaultSubjectTokenType              = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // RFC 8693 token-type URN, not a credential
	defaultSubjectTokenTypeGitHubActions = "urn:ietf:params:oauth:token-type:id_token"     //nolint:gosec // RFC 8693 token-type URN, not a credential
	envSubjectToken                      = "OIDC_TOKEN_SUBJECT_TOKEN"                      //nolint:gosec // env-var name, not a credential
	envSubjectTokenType                  = "OIDC_TOKEN_SUBJECT_TOKEN_TYPE"                 //nolint:gosec // env-var name, not a credential
	envSubjectTokenSource                = "OIDC_TOKEN_SUBJECT_TOKEN_SOURCE"               //nolint:gosec // env-var name, not a credential
)

// TokenExchange implements the RFC 8693 token exchange grant.
type TokenExchange struct {
	// Exported resolved values, readable by callers after Finalize.
	SubjectToken       string
	SubjectTokenType   string
	RequestedTokenType string
	Resources          []string
	SubjectTokenSource string

	// Private flag pointers, populated by RegisterFlags.
	subjectToken       *string
	subjectTokenFile   *string
	subjectTokenType   *string
	requestedTokenType *string
	resources          stringSliceFlag
	subjectTokenSource *string
}

var _ grant.Grant = (*TokenExchange)(nil)

func New() *TokenExchange { return &TokenExchange{} }

func (g *TokenExchange) Name() string { return "token-exchange" }

func (g *TokenExchange) WireGrant() string {
	return "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // RFC 8693 grant-type URN, not a credential
}

func (g *TokenExchange) Cacheable() bool    { return false }
func (g *TokenExchange) AutoEligible() bool { return false }

func (g *TokenExchange) Viable(_ grant.Environment, _ bool) bool { return true }

func (g *TokenExchange) RegisterFlags(fs *flag.FlagSet) {
	g.subjectToken = fs.String("subject-token", "", "subject_token for RFC 8693 token exchange (--grant-type=token-exchange); prefer --subject-token-file or $"+envSubjectToken+" over this flag")
	g.subjectTokenFile = fs.String("subject-token-file", "", "path to a file containing the subject_token (trailing newline trimmed); takes precedence over --subject-token")
	g.subjectTokenType = fs.String("subject-token-type", "", "subject_token_type per RFC 8693 §3 (--grant-type=token-exchange); defaults to the access_token type, or the id_token type when --subject-token-source=github-actions")
	g.requestedTokenType = fs.String("requested-token-type", "", "optional requested_token_type per RFC 8693 §2.1 (--grant-type=token-exchange); omitted from the request entirely when unset")
	g.subjectTokenSource = fs.String("subject-token-source", "", "auto-fetch subject_token from an external source instead of --subject-token: \"\" (manual, default) | github-actions (--grant-type=token-exchange only); mutually exclusive with --subject-token/--subject-token-file/$"+envSubjectToken)
	fs.Var(&g.resources, "resource", "target resource URI for RFC 8693 token exchange (--grant-type=token-exchange); repeatable for multiple resource params")
}

func (g *TokenExchange) Finalize(explicit map[string]bool, env grant.EnvFunc, fc map[string]any) error {
	// 1. Environment variables.
	if v := env(envSubjectToken); v != "" {
		g.SubjectToken = v
	}
	if v := env(envSubjectTokenType); v != "" {
		g.SubjectTokenType = v
	}
	if v := env(envSubjectTokenSource); v != "" {
		g.SubjectTokenSource = v
	}

	// 2. File config (keys match the JSON config schema).
	if fc != nil {
		if v, ok := fc["subject_token"].(string); ok {
			g.SubjectToken = v
		}
		if v, ok := fc["subject_token_type"].(string); ok {
			g.SubjectTokenType = v
		}
		if v, ok := fc["subject_token_source"].(string); ok {
			g.SubjectTokenSource = v
		}
		if v, ok := fc["requested_token_type"].(string); ok {
			g.RequestedTokenType = v
		}
		if v, ok := fc["resource"]; ok {
			if arr, ok := v.([]any); ok {
				res := make([]string, 0, len(arr))
				for _, item := range arr {
					if s, ok := item.(string); ok {
						res = append(res, s)
					}
				}
				if len(res) > 0 {
					g.Resources = res
				}
			}
		}
	}

	// 3. Explicitly-set flags win over env and file.
	if explicit["subject-token"] {
		g.SubjectToken = *g.subjectToken
	}
	if explicit["subject-token-type"] {
		g.SubjectTokenType = *g.subjectTokenType
	}
	if explicit["requested-token-type"] {
		g.RequestedTokenType = *g.requestedTokenType
	}
	if explicit["resource"] {
		g.Resources = []string(g.resources)
	}
	if explicit["subject-token-source"] {
		g.SubjectTokenSource = *g.subjectTokenSource
	}

	// 4. --subject-token-file always takes precedence over --subject-token /
	// env / file, mirroring --client-secret-file's precedence.
	if explicit["subject-token-file"] {
		tok, err := os.ReadFile(*g.subjectTokenFile)
		if err != nil {
			return fmt.Errorf("config: read --subject-token-file: %w", err)
		}
		g.SubjectToken = strings.TrimRight(string(tok), "\n")
	}

	// 5. Default subject_token_type once the source is known.
	if g.SubjectTokenType == "" {
		if g.SubjectTokenSource == "github-actions" {
			g.SubjectTokenType = defaultSubjectTokenTypeGitHubActions
		} else {
			g.SubjectTokenType = defaultSubjectTokenType
		}
	}

	return nil
}

func (g *TokenExchange) Validate() error {
	switch g.SubjectTokenSource {
	case "", "github-actions":
	default:
		return fmt.Errorf("config: invalid --subject-token-source %q (want \"\"|github-actions)", g.SubjectTokenSource)
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

// stringSliceFlag implements flag.Value for a repeatable string flag
// (e.g. --resource), appending on every Set call.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}
