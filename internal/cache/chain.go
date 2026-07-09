package cache

import (
	"context"
	"errors"
	"sync"
)

// Backend selects which Store backend(s) the CLI uses.
type Backend string

const (
	// BackendAuto tries the OS keychain first, falling back to the file
	// store only when the keychain backend is unavailable (not on a plain
	// miss). This is the default.
	BackendAuto Backend = "auto"
	// BackendKeychain enforces the OS keychain exclusively; no fallback.
	BackendKeychain Backend = "keychain"
	// BackendFile enforces the plaintext file store exclusively, matching
	// this CLI's original behavior.
	BackendFile Backend = "file"
)

// ChainStore implements Store by trying an ordered list of backends. A
// backend's ErrBackendUnavailable error causes the chain to try the next
// backend; any other error (including a plain miss) is not retried against
// later backends.
type ChainStore struct {
	Backends []Store
	// Logger receives a one-time notice when a backend is skipped as
	// unavailable. May be nil.
	Logger func(format string, args ...any)

	logOnce sync.Once
}

var _ Store = (*ChainStore)(nil)

func (c *ChainStore) logFallback(err error) {
	c.logOnce.Do(func() {
		if c.Logger != nil {
			c.Logger("cache: OS keychain unavailable (%v); falling back to file cache", err)
		}
	})
}

func (c *ChainStore) Load(ctx context.Context, issuer, clientID string) (Entry, bool, error) {
	var lastErr error
	for i, b := range c.Backends {
		e, ok, err := b.Load(ctx, issuer, clientID)
		if err == nil {
			return e, ok, nil
		}
		if errors.Is(err, ErrBackendUnavailable) && i < len(c.Backends)-1 {
			c.logFallback(err)
			lastErr = err
			continue
		}
		return Entry{}, false, err
	}
	return Entry{}, false, lastErr
}

func (c *ChainStore) Save(ctx context.Context, e Entry) error {
	var lastErr error
	for i, b := range c.Backends {
		err := b.Save(ctx, e)
		if err == nil {
			return nil
		}
		if errors.Is(err, ErrBackendUnavailable) && i < len(c.Backends)-1 {
			c.logFallback(err)
			lastErr = err
			continue
		}
		return err
	}
	return lastErr
}

// Delete removes the entry from every backend in the chain, best-effort, so
// a logout clears both a keychain entry and a leftover file entry (e.g. from
// a downgrade to --token-store=file). It returns the first non-not-found
// error encountered, but still attempts every backend.
func (c *ChainStore) Delete(ctx context.Context, issuer, clientID string) error {
	var firstErr error
	for _, b := range c.Backends {
		if err := b.Delete(ctx, issuer, clientID); err != nil && !errors.Is(err, ErrBackendUnavailable) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// WithLock always acquires the file backend's flock when one is present in
// the chain, even if the payload ultimately lives in keychain: this
// guarantees cross-process mutual exclusion is never silently dropped just
// because keychain happened to answer first. When no file backend is
// present (pure keychain-enforce mode), it falls through to the first
// backend's own WithLock (a process-local mutex for KeychainStore).
func (c *ChainStore) WithLock(ctx context.Context, issuer, clientID string, fn func() error) error {
	for _, b := range c.Backends {
		if fs, ok := b.(*Cache); ok {
			return fs.WithLock(ctx, issuer, clientID, fn)
		}
	}
	if len(c.Backends) == 0 {
		return fn()
	}
	return c.Backends[0].WithLock(ctx, issuer, clientID, fn)
}
