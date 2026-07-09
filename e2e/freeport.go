//go:build e2e

package e2e

import (
	"net"
	"testing"
)

// mustFreePort probes the OS for a currently-unused TCP port on 127.0.0.1.
// There is an inherent, small TOCTOU race between closing this probe
// listener and a later bind (e.g. Docker's port mapping) reusing the same
// port; callers that bind it externally should retry on a bind failure.
func mustFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close port probe listener: %v", err)
	}
	return port
}
