package cache

import (
	"context"
	"errors"
	"time"
)

// ErrBackendUnavailable signals that a Store backend cannot service requests
// at all right now (e.g. no keychain daemon reachable), as opposed to a
// genuine operational failure (permission denied, malformed data). Only this
// error class causes a ChainStore to try the next backend.
var ErrBackendUnavailable = errors.New("cache: backend unavailable")

// Entry is the cache record for a single (issuer, client_id) profile,
// independent of which Store backend persists it.
type Entry struct {
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"client_id"`
	AccessToken  string    `json:"access_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry"`
}

// Store persists and locks per-(issuer, client_id) profile Entries. It
// abstracts over the storage backend (plaintext file, OS keychain, or a
// fallback chain of both) so Runner never depends on a concrete backend.
//
// Load/Save error semantics: ok==false, err==nil means "no usable entry"
// (absent, corrupt, or backend reports not-found) — callers must treat this
// as a cache miss, not an error. err!=nil wrapping ErrBackendUnavailable means
// the backend itself can't be used right now; any other err is a genuine
// operational failure.
type Store interface {
	// Load returns the entry for (issuer, clientID).
	Load(ctx context.Context, issuer, clientID string) (Entry, bool, error)

	// Save atomically persists e, keyed by e.Issuer/e.ClientID.
	Save(ctx context.Context, e Entry) error

	// Delete removes the entry for (issuer, clientID). It is a no-op
	// (nil error) if no entry exists.
	Delete(ctx context.Context, issuer, clientID string) error

	// WithLock runs fn while holding whatever serialization primitive this
	// backend needs for the (issuer, clientID) profile.
	WithLock(ctx context.Context, issuer, clientID string, fn func() error) error
}
