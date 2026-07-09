package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sync"

	"github.com/zalando/go-keyring"
)

// keychainUser is the fixed "account" field for every keychain item this
// package creates. Each profile already gets its own unique service name
// (see keychainService), so user doesn't need to vary.
const keychainUser = "token"

// keychainProbeService is queried once per process to cheaply decide whether
// a keychain backend is reachable at all, without touching any real profile.
const keychainProbeService = "oidc-token:__probe__"

// KeychainStore persists Entries as JSON blobs in the OS keychain (macOS
// Keychain via the `security` CLI, Linux Secret Service via D-Bus), one item
// per (issuer, client_id) profile.
//
// WithLock only serializes callers within this process: OS keychains expose
// no cross-process advisory-lock primitive, and the underlying keychain
// daemon already serializes concurrent writes to a single item at the OS
// level. Callers that need cross-process mutual exclusion should prefer
// ChainStore, which reuses the file backend's flock for that purpose whenever
// a file backend is present.
type KeychainStore struct {
	mu sync.Mutex
}

// NewKeychainStore returns a KeychainStore. It performs no I/O; call Probe
// to check availability before relying on it exclusively.
func NewKeychainStore() *KeychainStore {
	return &KeychainStore{}
}

var _ Store = (*KeychainStore)(nil)

func keychainService(issuer, clientID string) string {
	return "oidc-token:" + profileKey(issuer, clientID)
}

// isUnavailable reports whether err indicates the keychain backend cannot be
// used at all right now (unsupported platform, missing `security` binary, no
// D-Bus session/Secret Service provider) as opposed to a per-item failure.
func isUnavailable(err error) bool {
	if errors.Is(err, keyring.ErrUnsupportedPlatform) {
		return true
	}
	var execErr *exec.Error
	if errors.As(err, &execErr) {
		return true
	}
	return false
}

// Probe performs a lightweight round-trip to check whether the keychain
// backend is reachable. Both success and ErrNotFound mean "available" (the
// backend answered); anything classified by isUnavailable means it isn't.
func (k *KeychainStore) Probe(ctx context.Context) error {
	_, err := runKeyringOp(ctx, func() (string, error) {
		return keyring.Get(keychainProbeService, keychainUser)
	})
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	if isUnavailable(err) {
		return fmt.Errorf("%w: %v", ErrBackendUnavailable, err)
	}
	// Any other error (e.g. a transient failure) is still treated as
	// unavailable for probing purposes: the caller only wants to know
	// whether it's safe to rely on this backend.
	return fmt.Errorf("%w: %v", ErrBackendUnavailable, err)
}

func (k *KeychainStore) Load(ctx context.Context, issuer, clientID string) (Entry, bool, error) {
	raw, err := runKeyringOp(ctx, func() (string, error) {
		return keyring.Get(keychainService(issuer, clientID), keychainUser)
	})
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return Entry{}, false, nil
		}
		if isUnavailable(err) {
			return Entry{}, false, fmt.Errorf("%w: %v", ErrBackendUnavailable, err)
		}
		return Entry{}, false, fmt.Errorf("cache: keychain read: %w", err)
	}
	var e Entry
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		// Corrupt entry is a miss, same policy as the file store.
		return Entry{}, false, nil
	}
	return e, true, nil
}

func (k *KeychainStore) Save(ctx context.Context, e Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("cache: marshal: %w", err)
	}
	_, err = runKeyringOp(ctx, func() (string, error) {
		return "", keyring.Set(keychainService(e.Issuer, e.ClientID), keychainUser, string(b))
	})
	if err != nil {
		if isUnavailable(err) {
			return fmt.Errorf("%w: %v", ErrBackendUnavailable, err)
		}
		return fmt.Errorf("cache: keychain write: %w", err)
	}
	return nil
}

func (k *KeychainStore) Delete(ctx context.Context, issuer, clientID string) error {
	_, err := runKeyringOp(ctx, func() (string, error) {
		return "", keyring.Delete(keychainService(issuer, clientID), keychainUser)
	})
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil
		}
		if isUnavailable(err) {
			return fmt.Errorf("%w: %v", ErrBackendUnavailable, err)
		}
		return fmt.Errorf("cache: keychain delete: %w", err)
	}
	return nil
}

// WithLock serializes callers within this process only; see the KeychainStore
// doc comment for why no cross-process guarantee is provided here.
func (k *KeychainStore) WithLock(_ context.Context, _, _ string, fn func() error) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return fn()
}

// runKeyringOp runs op in a goroutine and bounds it by ctx, since the
// underlying `security`/D-Bus calls accept no context of their own and can
// hang (e.g. a locked keychain prompting for a password).
func runKeyringOp(ctx context.Context, op func() (string, error)) (string, error) {
	type result struct {
		val string
		err error
	}
	done := make(chan result, 1)
	go func() {
		val, err := op()
		done <- result{val, err}
	}()
	select {
	case r := <-done:
		return r.val, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
