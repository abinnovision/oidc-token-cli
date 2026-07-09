package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
)

// fakeStore is a minimal in-memory Store double with injectable errors, used
// to test ChainStore's fallback logic in isolation from any real backend.
type fakeStore struct {
	entries   map[string]Entry
	loadErr   error
	saveErr   error
	deleteErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{entries: map[string]Entry{}}
}

func (f *fakeStore) key(issuer, clientID string) string { return issuer + "\x00" + clientID }

func (f *fakeStore) Load(_ context.Context, issuer, clientID string) (Entry, bool, error) {
	if f.loadErr != nil {
		return Entry{}, false, f.loadErr
	}
	e, ok := f.entries[f.key(issuer, clientID)]
	return e, ok, nil
}

func (f *fakeStore) Save(_ context.Context, e Entry) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.entries[f.key(e.Issuer, e.ClientID)] = e
	return nil
}

func (f *fakeStore) Delete(_ context.Context, issuer, clientID string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.entries, f.key(issuer, clientID))
	return nil
}

func (f *fakeStore) WithLock(_ context.Context, _, _ string, fn func() error) error {
	return fn()
}

var _ Store = (*fakeStore)(nil)

func TestChainStore_Load_FallsThroughOnUnavailable(t *testing.T) {
	first := newFakeStore()
	first.loadErr = fmt.Errorf("%w: no daemon", ErrBackendUnavailable)
	second := newFakeStore()
	second.entries[second.key("iss", "cid")] = Entry{Issuer: "iss", ClientID: "cid", AccessToken: "from-second"}

	c := &ChainStore{Backends: []Store{first, second}}
	e, ok, err := c.Load(context.Background(), "iss", "cid")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ok || e.AccessToken != "from-second" {
		t.Fatalf("got %+v ok=%v, want fallback to second backend", e, ok)
	}
}

func TestChainStore_Load_PlainMissDoesNotFallThrough(t *testing.T) {
	first := newFakeStore() // no error, just genuinely empty
	second := newFakeStore()
	second.entries[second.key("iss", "cid")] = Entry{Issuer: "iss", ClientID: "cid", AccessToken: "from-second"}

	c := &ChainStore{Backends: []Store{first, second}}
	_, ok, err := c.Load(context.Background(), "iss", "cid")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ok {
		t.Fatal("a plain miss on the first backend must not fall through to the second")
	}
}

func TestChainStore_Load_NonUnavailableErrorDoesNotFallThrough(t *testing.T) {
	first := newFakeStore()
	first.loadErr = errors.New("permission denied")
	second := newFakeStore()
	second.entries[second.key("iss", "cid")] = Entry{Issuer: "iss", ClientID: "cid", AccessToken: "from-second"}

	c := &ChainStore{Backends: []Store{first, second}}
	_, _, err := c.Load(context.Background(), "iss", "cid")
	if err == nil || errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("err = %v, want the genuine (non-unavailable) error to propagate untouched", err)
	}
}

func TestChainStore_EnforceMode_PropagatesUnavailableUntouched(t *testing.T) {
	only := newFakeStore()
	only.loadErr = fmt.Errorf("%w: no daemon", ErrBackendUnavailable)

	c := &ChainStore{Backends: []Store{only}} // single-backend "enforce" mode
	_, _, err := c.Load(context.Background(), "iss", "cid")
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("err = %v, want ErrBackendUnavailable to propagate when there's no next backend", err)
	}
}

func TestChainStore_Save_FallsThroughOnUnavailable(t *testing.T) {
	first := newFakeStore()
	first.saveErr = fmt.Errorf("%w: no daemon", ErrBackendUnavailable)
	second := newFakeStore()

	c := &ChainStore{Backends: []Store{first, second}}
	e := Entry{Issuer: "iss", ClientID: "cid", AccessToken: "at"}
	if err := c.Save(context.Background(), e); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok := second.entries[second.key("iss", "cid")]
	if !ok || got.AccessToken != "at" {
		t.Fatalf("expected the entry to land in the fallback backend, got %+v ok=%v", got, ok)
	}
}

func TestChainStore_FallbackLoggedExactlyOncePerProcess(t *testing.T) {
	first := newFakeStore()
	first.loadErr = fmt.Errorf("%w: no daemon", ErrBackendUnavailable)
	second := newFakeStore()

	var logCount int
	c := &ChainStore{Backends: []Store{first, second}, Logger: func(string, ...any) { logCount++ }}
	for i := 0; i < 5; i++ {
		if _, _, err := c.Load(context.Background(), "iss", "cid"); err != nil {
			t.Fatalf("Load: %v", err)
		}
	}
	if logCount != 1 {
		t.Fatalf("logCount = %d, want exactly 1 across repeated calls", logCount)
	}
}

func TestChainStore_WithLock_PrefersFileBackend(t *testing.T) {
	fileStore := New(t.TempDir())
	keychain := newFakeStore()

	c := &ChainStore{Backends: []Store{keychain, fileStore}}
	called := false
	if err := c.WithLock(context.Background(), "iss", "cid", func() error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("WithLock: %v", err)
	}
	if !called {
		t.Fatal("fn was never invoked")
	}
	// The file backend's lock file must actually have been touched, proving
	// the flock path (not just the fake's no-op WithLock) was used.
	if _, err := os.Stat(fileStore.lockPath("iss", "cid")); err != nil {
		t.Fatalf("expected the file backend's lock file to exist: %v", err)
	}
}

func TestChainStore_Delete_BestEffortAcrossBackends(t *testing.T) {
	first := newFakeStore()
	first.entries[first.key("iss", "cid")] = Entry{Issuer: "iss", ClientID: "cid"}
	second := newFakeStore()
	second.entries[second.key("iss", "cid")] = Entry{Issuer: "iss", ClientID: "cid"}

	c := &ChainStore{Backends: []Store{first, second}}
	if err := c.Delete(context.Background(), "iss", "cid"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := first.entries[first.key("iss", "cid")]; ok {
		t.Fatal("expected first backend's entry to be deleted")
	}
	if _, ok := second.entries[second.key("iss", "cid")]; ok {
		t.Fatal("expected second backend's entry to be deleted")
	}
}
