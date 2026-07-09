package oidc

import (
	"context"
	"net/http"
	"time"

	upstream "github.com/coreos/go-oidc/v3/oidc"
)

// defaultHTTPTimeout bounds every HTTP round-trip this package makes so an
// unreachable or wedged issuer can never hang a caller forever.
const defaultHTTPTimeout = 30 * time.Second

var defaultHTTPClient = &http.Client{Timeout: defaultHTTPTimeout}

// withHTTPClient returns ctx carrying an HTTP client with defaultHTTPTimeout.
// x/oauth2 and go-oidc both read the same context key, so this one call
// covers every HTTP request either library makes on ctx's behalf.
func withHTTPClient(ctx context.Context) context.Context {
	return upstream.ClientContext(ctx, defaultHTTPClient)
}
