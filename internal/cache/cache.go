package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// lockAcquireTimeout bounds how long WithLock waits for a contended lock, so
// a wedged holder (crashed mid-refresh) can't hang callers forever.
const lockAcquireTimeout = 30 * time.Second

const lockRetryDelay = 50 * time.Millisecond

// ErrLockTimeout is returned when WithLock could not acquire the profile
// lock within lockAcquireTimeout, or the caller's ctx was done first.
var ErrLockTimeout = errors.New("cache: timed out waiting for the profile lock")

// Cache is a directory of per-profile JSON token files. It implements Store.
type Cache struct {
	Dir string
}

var _ Store = (*Cache)(nil)

// New returns a Cache rooted at dir. The directory is created lazily on
// first write, with 0700 permissions.
func New(dir string) *Cache {
	return &Cache{Dir: dir}
}

// DefaultDir returns the default cache directory: $XDG_CACHE_HOME/oidc-token
// if XDG_CACHE_HOME is set, else ~/.cache/oidc-token.
func DefaultDir(getenv func(string) string) (string, error) {
	if xdg := getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "oidc-token"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cache: resolve home directory: %w", err)
	}
	return filepath.Join(home, ".cache", "oidc-token"), nil
}

// profileKey deterministically maps (issuer, clientID) to a filename-safe
// key so multiple profiles can live side by side in the same cache dir.
func profileKey(issuer, clientID string) string {
	sum := sha256.Sum256([]byte(issuer + "\x00" + clientID))
	return hex.EncodeToString(sum[:])
}

func (c *Cache) path(issuer, clientID string) string {
	return filepath.Join(c.Dir, profileKey(issuer, clientID)+".json")
}

// Path returns the on-disk file path for the given (issuer, clientID)
// profile. Exposed for tests that need to manipulate the cache file
// directly (e.g. simulating corruption).
func (c *Cache) Path(issuer, clientID string) string {
	return c.path(issuer, clientID)
}

func (c *Cache) lockPath(issuer, clientID string) string {
	return filepath.Join(c.Dir, profileKey(issuer, clientID)+".lock")
}

// ensureDir creates c.Dir if absent and enforces 0700 permissions on it
// either way, since MkdirAll alone only sets permissions at creation time.
func (c *Cache) ensureDir() error {
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return fmt.Errorf("cache: create dir: %w", err)
	}
	if err := os.Chmod(c.Dir, 0o700); err != nil { //nolint:gosec // 0700 on a directory needs the execute bit for traversal; not a file-permission issue
		return fmt.Errorf("cache: chmod dir: %w", err)
	}
	return nil
}

// Load reads the cache entry for (issuer, clientID). An absent or
// unparseable file is reported as ok==false, err==nil (re-authenticate);
// other I/O errors (e.g. permission denied) return a non-nil error.
func (c *Cache) Load(_ context.Context, issuer, clientID string) (Entry, bool, error) {
	b, err := os.ReadFile(c.path(issuer, clientID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Entry{}, false, nil
		}
		return Entry{}, false, fmt.Errorf("cache: read: %w", err)
	}
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		// Corrupt cache is a miss, not an error.
		return Entry{}, false, nil
	}
	return e, true, nil
}

// Save atomically writes entry to its cache file: dir 0700, file 0600,
// write-to-temp-then-rename in the same directory so a crash never leaves a
// partially written cache file.
func (c *Cache) Save(_ context.Context, e Entry) error {
	if err := c.ensureDir(); err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("cache: marshal: %w", err)
	}

	dest := c.path(e.Issuer, e.ClientID)
	tmp, err := os.CreateTemp(c.Dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("cache: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	// success guards a best-effort cleanup of tmp if we fail before rename.
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cache: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cache: close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("cache: chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("cache: rename temp file: %w", err)
	}
	success = true
	return nil
}

// WithLock runs fn while holding an advisory file lock scoped to the
// (issuer, clientID) profile, waiting up to lockAcquireTimeout (or ctx's
// deadline, whichever is sooner) so a wedged holder can't hang forever.
func (c *Cache) WithLock(ctx context.Context, issuer, clientID string, fn func() error) error {
	if err := c.ensureDir(); err != nil {
		return err
	}
	lockCtx, cancel := context.WithTimeout(ctx, lockAcquireTimeout)
	defer cancel()

	fl := flock.New(c.lockPath(issuer, clientID))
	locked, err := fl.TryLockContext(lockCtx, lockRetryDelay)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLockTimeout, err)
	}
	if !locked {
		return ErrLockTimeout
	}
	defer func() { _ = fl.Unlock() }()
	return fn()
}

// Delete removes the cache file for (issuer, clientID). Absent files are not
// an error.
func (c *Cache) Delete(_ context.Context, issuer, clientID string) error {
	if err := os.Remove(c.path(issuer, clientID)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("cache: delete: %w", err)
	}
	return nil
}
