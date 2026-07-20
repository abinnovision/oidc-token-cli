package subjecttoken

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// defaultHTTPTimeout bounds the GitHub Actions OIDC token request so a
// wedged runner (or a broken proxy) can never hang the caller forever.
const defaultHTTPTimeout = 15 * time.Second

// DefaultTokenTypeGitHubActions is the RFC 8693 token-type URN for the
// id_token GitHub Actions' native OIDC provider issues.
const DefaultTokenTypeGitHubActions = "urn:ietf:params:oauth:token-type:id_token" //nolint:gosec // RFC 8693 token-type URN, not a credential

var defaultHTTPClient = &http.Client{Timeout: defaultHTTPTimeout}

// maxResponseBytes bounds how much of the token response body is read, so a
// misbehaving endpoint cannot exhaust memory.
const maxResponseBytes = 1 << 20 // 1 MiB

// githubActionsTokenResponse is the response body from
// ACTIONS_ID_TOKEN_REQUEST_URL: {"value": "<jwt>", "count": N}.
type githubActionsTokenResponse struct {
	Value string `json:"value"`
}

// FetchGitHubActions resolves an RFC 8693 subject_token from GitHub
// Actions' native OIDC provider: it reads ACTIONS_ID_TOKEN_REQUEST_URL and
// ACTIONS_ID_TOKEN_REQUEST_TOKEN via getenv, GETs
// "<url>&audience=<audience>" (audience omitted if empty) with
// "Authorization: bearer <token>", and returns the response's "value"
// field.
//
// getenv and httpClient are injected so tests can fake both the GitHub
// Actions metadata (no real env vars) and the HTTP round-trip (no real
// network). A nil httpClient uses a package-level client with
// defaultHTTPTimeout.
func FetchGitHubActions(ctx context.Context, getenv func(string) string, audience string, httpClient *http.Client) (string, error) {
	if httpClient == nil {
		httpClient = defaultHTTPClient
	}

	reqURL := getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqToken := getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqToken == "" {
		return "", fmt.Errorf("subjecttoken: --subject-token-source=github-actions requires $ACTIONS_ID_TOKEN_REQUEST_URL and $ACTIONS_ID_TOKEN_REQUEST_TOKEN, set by GitHub Actions only when the job has \"permissions: id-token: write\"")
	}

	parsedURL, err := url.Parse(reqURL)
	if err != nil {
		return "", fmt.Errorf("subjecttoken: parse $ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	if audience != "" {
		q := parsedURL.Query()
		q.Set("audience", audience)
		parsedURL.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("subjecttoken: build github-actions token request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+reqToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("subjecttoken: fetch github-actions token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("subjecttoken: read github-actions token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("subjecttoken: github-actions token endpoint returned %s: %s", resp.Status, body)
	}

	var parsed githubActionsTokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("subjecttoken: parse github-actions token response: %w", err)
	}
	if parsed.Value == "" {
		return "", fmt.Errorf("subjecttoken: github-actions token response has empty \"value\"")
	}

	return parsed.Value, nil
}

// GitHubActions implements Source using GitHub Actions' native OIDC
// provider.
type GitHubActions struct {
	Getenv     func(string) string
	HTTPClient *http.Client
}

func (g *GitHubActions) Name() string { return "github-actions" }

func (g *GitHubActions) DefaultTokenType() string {
	return DefaultTokenTypeGitHubActions
}

func (g *GitHubActions) Fetch(ctx context.Context, audience string) (string, error) {
	return FetchGitHubActions(ctx, g.Getenv, audience, g.HTTPClient)
}

var _ Source = (*GitHubActions)(nil)
