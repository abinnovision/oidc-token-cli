// Package subjecttoken resolves an RFC 8693 subject_token from an external,
// ambient source instead of requiring the caller to supply one explicitly.
// Today it supports GitHub Actions' native OIDC token endpoint
// (ACTIONS_ID_TOKEN_REQUEST_URL/ACTIONS_ID_TOKEN_REQUEST_TOKEN); more CI
// providers (e.g. GitLab CI) can be added as siblings.
package subjecttoken
