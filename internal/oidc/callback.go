package oidc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// AuthorizationError is returned when the loopback callback receives an
// OAuth2 "error" query parameter, i.e. the authorization server rejected
// the request before any code was issued.
type AuthorizationError struct {
	Code        string
	Description string
}

func (e *AuthorizationError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("oidc: authorization error: %s: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("oidc: authorization error: %s", e.Code)
}

type callbackResult struct {
	code string
	err  error
}

// awaitCallback binds and listens on ln for the authorization redirect to
// /callback, extracting the OAuth2 authorization response's code (or
// error) query parameter once a request arrives whose "state" matches
// expectedState.
//
// A request with a missing or mismatched state (browser preconnect, favicon
// probe, forged local request) gets a 4xx response and does not end the
// flow — the server keeps listening (bounded by ctx) for the genuine
// redirect, per RFC 6749 §10.12's state check.
func awaitCallback(ctx context.Context, ln net.Listener, expectedState string) (code string, err error) {
	resultCh := make(chan callbackResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != expectedState {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Invalid or missing state parameter.")
			return
		}

		var res callbackResult
		if e := q.Get("error"); e != "" {
			res.err = &AuthorizationError{Code: e, Description: q.Get("error_description")}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintln(w, "Login failed. You can close this window and return to the terminal.")
		} else {
			res.code = q.Get("code")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintln(w, "Login complete. You can close this window and return to the terminal.")
		}
		select {
		case resultCh <- res:
		default:
			// A valid-state result already completed the flow (e.g. a
			// duplicate/replayed redirect); nothing more to do.
		}
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	select {
	case res := <-resultCh:
		_ = srv.Shutdown(context.Background())
		return res.code, res.err
	case <-ctx.Done():
		_ = srv.Close()
		return "", fmt.Errorf("oidc: timed out waiting for the authorization callback: %w", ctx.Err())
	}
}
