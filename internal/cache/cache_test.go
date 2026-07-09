package cache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestSaveLoad_RoundTrip(t *testing.T) {
	c := New(t.TempDir())
	want := Entry{
		Issuer:       "https://issuer.example",
		ClientID:     "client-a",
		AccessToken:  "at",
		IDToken:      "it",
		RefreshToken: "rt",
		Expiry:       time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := c.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok, err := c.Load(want.Issuer, want.ClientID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ok {
		t.Fatal("Load: expected ok=true after Save")
	}
	if got.AccessToken != want.AccessToken || got.IDToken != want.IDToken ||
		got.RefreshToken != want.RefreshToken || !got.Expiry.Equal(want.Expiry) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestSave_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits not applicable on windows")
	}
	dir := t.TempDir()
	// Force MkdirAll on a fresh subdirectory so we can assert its perms too.
	sub := filepath.Join(dir, "sub")
	c := New(sub)
	e := Entry{Issuer: "iss", ClientID: "cid"}
	if err := c.Save(e); err != nil {
		t.Fatalf("Save: %v", err)
	}

	dirInfo, err := os.Stat(sub)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("cache dir perm = %o, want 0700", perm)
	}

	fileInfo, err := os.Stat(c.path(e.Issuer, e.ClientID))
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("cache file perm = %o, want 0600", perm)
	}
}

func TestSave_TightensPreexistingLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits not applicable on windows")
	}
	dir := t.TempDir()
	// Simulate a pre-existing dir with looser perms than MkdirAll would set.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	c := New(dir)
	if err := c.Save(Entry{Issuer: "iss", ClientID: "cid"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("cache dir perm = %o, want 0700 (Save must tighten a pre-existing loosely-permissioned dir)", perm)
	}
}

func TestSave_NoLeftoverTempFiles(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)
	if err := c.Save(Entry{Issuer: "iss", ClientID: "cid"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			t.Fatalf("unexpected leftover file after atomic Save: %s", e.Name())
		}
	}
}

func TestLoad_AbsentCache_TreatedAsMiss(t *testing.T) {
	c := New(t.TempDir())
	_, ok, err := c.Load("https://issuer.example", "client-a")
	if err != nil {
		t.Fatalf("Load on absent cache returned error: %v", err)
	}
	if ok {
		t.Fatal("Load on absent cache must report ok=false")
	}
}

func TestLoad_CorruptCache_TreatedAsMiss(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)
	e := Entry{Issuer: "iss", ClientID: "cid"}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.path(e.Issuer, e.ClientID), []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, ok, err := c.Load(e.Issuer, e.ClientID)
	if err != nil {
		t.Fatalf("corrupt cache must be a miss, not an error: %v", err)
	}
	if ok {
		t.Fatal("corrupt cache must report ok=false")
	}
}

func TestMultiProfile_Independence(t *testing.T) {
	c := New(t.TempDir())
	a := Entry{Issuer: "https://a.example", ClientID: "client-a", AccessToken: "token-a"}
	b := Entry{Issuer: "https://b.example", ClientID: "client-b", AccessToken: "token-b"}
	if err := c.Save(a); err != nil {
		t.Fatal(err)
	}
	if err := c.Save(b); err != nil {
		t.Fatal(err)
	}
	if c.path(a.Issuer, a.ClientID) == c.path(b.Issuer, b.ClientID) {
		t.Fatal("distinct profiles must map to distinct cache files")
	}
	gotA, ok, err := c.Load(a.Issuer, a.ClientID)
	if err != nil || !ok || gotA.AccessToken != "token-a" {
		t.Fatalf("profile a: got %+v ok=%v err=%v", gotA, ok, err)
	}
	gotB, ok, err := c.Load(b.Issuer, b.ClientID)
	if err != nil || !ok || gotB.AccessToken != "token-b" {
		t.Fatalf("profile b: got %+v ok=%v err=%v", gotB, ok, err)
	}
}

func TestSave_RotatedRefreshTokenPersisted(t *testing.T) {
	c := New(t.TempDir())
	e := Entry{Issuer: "iss", ClientID: "cid", RefreshToken: "rt-1"}
	if err := c.Save(e); err != nil {
		t.Fatal(err)
	}
	e.RefreshToken = "rt-2-rotated"
	if err := c.Save(e); err != nil {
		t.Fatal(err)
	}
	got, ok, err := c.Load(e.Issuer, e.ClientID)
	if err != nil || !ok {
		t.Fatalf("Load: %+v ok=%v err=%v", got, ok, err)
	}
	if got.RefreshToken != "rt-2-rotated" {
		t.Fatalf("RefreshToken = %q, want rotated value", got.RefreshToken)
	}
}

func TestWithLock_SerializesConcurrentCriticalSections(t *testing.T) {
	c := New(t.TempDir())
	issuer, clientID := "iss", "cid"

	var mu sync.Mutex
	active := 0
	maxActive := 0
	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			err := c.WithLock(context.Background(), issuer, clientID, func() error {
				mu.Lock()
				active++
				if active > maxActive {
					maxActive = active
				}
				mu.Unlock()

				time.Sleep(5 * time.Millisecond)

				mu.Lock()
				active--
				mu.Unlock()
				return nil
			})
			if err != nil {
				t.Errorf("WithLock: %v", err)
			}
		}()
	}
	wg.Wait()
	if maxActive != 1 {
		t.Fatalf("max concurrent critical sections = %d, want 1 (lock did not serialize)", maxActive)
	}
}

func TestWithLock_BoundedByCallerContext(t *testing.T) {
	c := New(t.TempDir())
	issuer, clientID := "iss", "cid"

	// A holder that acquires the lock and never releases it on its own
	// (simulating a wedged/crashed process) — a follower with a short ctx
	// timeout must not be blocked forever waiting on it.
	holderStarted := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- c.WithLock(context.Background(), issuer, clientID, func() error {
			close(holderStarted)
			<-release
			return nil
		})
	}()
	<-holderStarted
	defer func() {
		close(release)
		<-holderDone
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := c.WithLock(ctx, issuer, clientID, func() error {
		t.Fatal("fn must not run: the lock is held elsewhere and the caller's ctx should time out first")
		return nil
	})
	elapsed := time.Since(start)

	if !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("err = %v, want ErrLockTimeout", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("WithLock took %v to give up, want bounded by the caller's short ctx timeout", elapsed)
	}
}
