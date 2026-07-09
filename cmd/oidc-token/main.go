// Command oidc-token-cli mints and prints an OIDC token for a generic public
// client, using cached credentials and silent refresh where possible.
//
// This file is the only place in the program that writes to stdout. On
// success it writes exactly the token bytes (or, with --all, a JSON
// document) and exits 0. On any failure it writes a message to stderr,
// writes nothing to stdout, and exits non-zero.
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
	"github.com/abinnovision/oidc-token-cli/internal/output"
	"github.com/abinnovision/oidc-token-cli/internal/runner"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, newRealSource))
}

// newSourceFunc builds the network-facing TokenSource for a resolved
// config; tests inject a fake in its place.
type newSourceFunc func(cfg *config.Config) runner.TokenSource

// run is main's testable core. Every write to stdout happens in exactly one
// place, guarded by err == nil, so a bug elsewhere cannot leak a partial or
// empty token onto stdout with a zero exit code.
func run(args []string, stdout, stderr io.Writer, newSource newSourceFunc) int {
	cfg, err := config.Parse(args, stderr, config.Env{Getenv: os.Getenv})
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// Usage was already written to stderr by the flag package;
			// --help is a successful, informational invocation.
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 1
	}

	rnr := &runner.Runner{
		Cache:  cache.New(cfg.CacheDir),
		Source: newSource(cfg),
		Config: cfg,
		Stderr: stderr,
	}

	result, err := rnr.Run(context.Background())
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	// Build the full output in memory first: a write failure partway
	// through must never leave a partial token on stdout.
	var buf bytes.Buffer
	if cfg.All {
		err = output.WriteAll(&buf, result)
	} else {
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
