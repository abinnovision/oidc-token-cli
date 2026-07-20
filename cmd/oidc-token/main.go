// Command oidc-token-cli mints and prints an OIDC token for a generic public
// client, using cached credentials and silent refresh where possible.
//
// This file is the only place in the program that writes to stdout. On
// success it writes exactly the selected --format's output (bare token
// bytes, a JSON document, or an ExecCredential envelope) and exits 0. On
// any failure it writes a message to stderr, writes nothing to stdout, and
// exits non-zero.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/abinnovision/oidc-token-cli/internal/cache"
	"github.com/abinnovision/oidc-token-cli/internal/config"
	"github.com/abinnovision/oidc-token-cli/internal/grant"
	grantauthcode "github.com/abinnovision/oidc-token-cli/internal/grant/authcode"
	grantdevicecode "github.com/abinnovision/oidc-token-cli/internal/grant/devicecode"
	granttokenexchange "github.com/abinnovision/oidc-token-cli/internal/grant/tokenexchange"
	"github.com/abinnovision/oidc-token-cli/internal/output"
	"github.com/abinnovision/oidc-token-cli/internal/runner"
	"github.com/abinnovision/oidc-token-cli/internal/subjecttoken"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, newRealSource, newRealTokenExchangeSource))
}

// newSourceFunc builds the network-facing TokenSource for a resolved
// config; tests inject a fake in its place.
type newSourceFunc func(cfg *config.Config) runner.TokenSource

// tokenExchanger performs an RFC 8693 token exchange. It is deliberately
// not part of runner.TokenSource: token exchange is never cached and never
// goes through the cache/refresh/login pipeline runner.Runner orchestrates.
type tokenExchanger interface {
	TokenExchange(ctx context.Context, subjectToken, subjectTokenType, requestedTokenType string, resources []string) (output.Result, error)
}

// newTokenExchangeFunc builds the network-facing tokenExchanger for a
// resolved config; tests inject a fake in its place.
type newTokenExchangeFunc func(cfg *config.Config) tokenExchanger

// buildStore constructs the cache.Store selected by cfg.TokenStore.
// --token-store=keychain probes the keychain up front and fails fast with a
// clear error rather than surfacing a confusing failure later.
func buildStore(ctx context.Context, cfg *config.Config, stderr io.Writer) (cache.Store, error) {
	switch cfg.TokenStore {
	case cache.BackendFile:
		return cache.New(cfg.TokenStoreDir), nil
	case cache.BackendKeychain:
		ks := cache.NewKeychainStore()
		if err := ks.Probe(ctx); err != nil {
			return nil, fmt.Errorf("--token-store=keychain requires a working OS keychain: %w", err)
		}
		return ks, nil
	case cache.BackendNone:
		return &cache.NoopStore{}, nil
	default: // cache.BackendAuto
		return &cache.ChainStore{
			Backends: []cache.Store{cache.NewKeychainStore(), cache.New(cfg.TokenStoreDir)},
			Logger: func(format string, args ...any) {
				fmt.Fprintf(stderr, format+"\n", args...)
			},
		}, nil
	}
}

// run is main's testable core. Every write to stdout happens in exactly one
// place, guarded by err == nil, so a bug elsewhere cannot leak a partial or
// empty token onto stdout with a zero exit code.
func run(args []string, stdout, stderr io.Writer, newSource newSourceFunc, newTokenExchange newTokenExchangeFunc) int {
	sources := []subjecttoken.Source{
		&subjecttoken.GitHubActions{Getenv: os.Getenv},
	}
	te := granttokenexchange.New(sources)
	grants := []grant.Grant{
		grantauthcode.New(),
		grantdevicecode.New(),
		te,
	}
	cfg, err := config.Parse(args, stderr, config.Env{Getenv: os.Getenv}, grants)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// Usage was already written to stderr by the flag package;
			// --help is a successful, informational invocation.
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	te.Audience = cfg.Audience

	ctx := context.Background()

	// Token exchange is never cached and never goes through
	// runner.Runner's cache/refresh/login pipeline, so it bypasses
	// buildStore entirely -- unlike --logout, which still needs a store to
	// delete an entry from.
	if cfg.GrantType == config.GrantTokenExchange {
		subjectToken, err := te.ResolveSubjectToken(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		result, err := newTokenExchange(cfg).TokenExchange(ctx, subjectToken, cfg.SubjectTokenType, cfg.RequestedTokenType, cfg.Resources)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		return writeResult(stdout, stderr, cfg, result, os.Getenv)
	}

	store, err := buildStore(ctx, cfg, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	if cfg.Logout {
		rnr := &runner.Runner{Cache: store, Config: cfg, Stderr: stderr}
		if err := rnr.Logout(ctx); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		return 0
	}

	rnr := &runner.Runner{
		Cache:  store,
		Source: newSource(cfg),
		Config: cfg,
		Stderr: stderr,
	}

	result, err := rnr.Run(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	return writeResult(stdout, stderr, cfg, result, os.Getenv)
}

// writeResult writes result to stdout in the format selected by
// cfg.Format: a bare token, a full JSON document, or a Kubernetes
// ExecCredential envelope. The full output is built in memory first: a
// write failure partway through must never leave a partial token on
// stdout.
func writeResult(stdout, stderr io.Writer, cfg *config.Config, result output.Result, getenv func(string) string) int {
	var buf bytes.Buffer
	var err error
	switch cfg.Format {
	case config.OutputFormatJSON:
		err = output.WriteAll(&buf, result)
	case config.OutputFormatExecCredential:
		err = output.WriteExecCredential(&buf, result, output.TokenType(cfg.TokenType), output.ExecCredentialAPIVersion(getenv))
	default:
		err = output.WriteBare(&buf, result, output.TokenType(cfg.TokenType))
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	if _, err := stdout.Write(buf.Bytes()); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}
