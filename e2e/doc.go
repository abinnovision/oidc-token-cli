//go:build e2e

// Package e2e runs the CLI's OIDC flows against a real dexidp/dex instance
// started via testcontainers-go, as a compliance/smoke tier on top of the
// fast, in-process internal/oidctest-backed integration suite. It requires
// Docker and is excluded from normal builds/tests by the e2e build tag; run
// with `go test -tags e2e ./e2e/...`.
package e2e
