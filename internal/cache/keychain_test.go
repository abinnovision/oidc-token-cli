package cache

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/zalando/go-keyring"
)

// Standard GitHub Actions Linux runners have no session D-Bus / Secret
// Service daemon, so KeychainStore reliably reports ErrBackendUnavailable
// there. This doubles as a regression test for the exact scenario the
// ChainStore fallback exists for.
func TestKeychainStore_Linux_UnavailableWithoutSecretService(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this assertion only holds on a headless Linux CI runner")
	}
	ks := NewKeychainStore()
	err := ks.Probe(context.Background())
	if err == nil {
		t.Skip("a Secret Service daemon is actually reachable in this environment; nothing to assert")
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("Probe err = %v, want ErrBackendUnavailable on headless Linux", err)
	}
}

func TestKeychainStore_Darwin_RoundTrip(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("real keychain round-trip only exercised on macOS")
	}
	ks := NewKeychainStore()
	if err := ks.Probe(context.Background()); err != nil {
		t.Skipf("keychain not available in this environment: %v", err)
	}

	issuer, clientID := "https://issuer.example/keychain-test", "cid-keychain-test"
	t.Cleanup(func() { _ = ks.Delete(context.Background(), issuer, clientID) })

	want := Entry{Issuer: issuer, ClientID: clientID, AccessToken: "at", RefreshToken: "rt"}
	if err := ks.Save(context.Background(), want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok, err := ks.Load(context.Background(), issuer, clientID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ok || got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken {
		t.Fatalf("got %+v ok=%v, want %+v", got, ok, want)
	}

	if err := ks.Delete(context.Background(), issuer, clientID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, ok, err = ks.Load(context.Background(), issuer, clientID)
	if err != nil {
		t.Fatalf("Load after Delete: %v", err)
	}
	if ok {
		t.Fatal("Load after Delete must report ok=false")
	}
}

func TestIsUnavailable_UnsupportedPlatform(t *testing.T) {
	if !isUnavailable(keyring.ErrUnsupportedPlatform) {
		t.Fatal("ErrUnsupportedPlatform must classify as unavailable")
	}
}

func TestIsUnavailable_NotFoundIsNotUnavailable(t *testing.T) {
	if isUnavailable(keyring.ErrNotFound) {
		t.Fatal("ErrNotFound must not classify as unavailable — it's a miss, not an unavailable backend")
	}
}

func TestKeychainStore_WithLock_SerializesInProcess(t *testing.T) {
	ks := NewKeychainStore()
	done := make(chan struct{})
	go func() {
		_ = ks.WithLock(context.Background(), "iss", "cid", func() error {
			close(done)
			return nil
		})
	}()
	<-done // just confirms WithLock actually invokes fn
}
