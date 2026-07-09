package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHTTPTimeout_BoundsStalledDiscovery proves a discovery endpoint that
// never responds does not hang Discover forever. Shrinks the shared
// client's timeout (safe: no t.Parallel in this package) instead of
// waiting out the real 30s default.
func TestHTTPTimeout_BoundsStalledDiscovery(t *testing.T) {
	orig := defaultHTTPClient.Timeout
	defaultHTTPClient.Timeout = 200 * time.Millisecond
	defer func() { defaultHTTPClient.Timeout = orig }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respond after the client timeout but not forever, since
		// httptest.Server.Close blocks until outstanding requests finish.
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	start := time.Now()
	_, err := Discover(context.Background(), srv.URL, "cid")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a stalled discovery endpoint")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Discover took %v to fail, want bounded by the HTTP client timeout", elapsed)
	}
}
