package cache

import (
	"context"
	"testing"
)

func TestNoopStore_LoadAlwaysMisses(t *testing.T) {
	var s NoopStore
	e, ok, err := s.Load(context.Background(), "https://issuer.example", "cid")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ok {
		t.Fatal("Load: ok = true, want clean miss")
	}
	if e != (Entry{}) {
		t.Fatalf("Load: entry = %+v, want zero value", e)
	}
}

func TestNoopStore_SaveIsNoop(t *testing.T) {
	var s NoopStore
	if err := s.Save(context.Background(), Entry{Issuer: "https://issuer.example", ClientID: "cid", AccessToken: "at"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, ok, _ := s.Load(context.Background(), "https://issuer.example", "cid"); ok {
		t.Fatal("Load after Save: ok = true, want Save to have persisted nothing")
	}
}

func TestNoopStore_DeleteIsNoop(t *testing.T) {
	var s NoopStore
	if err := s.Delete(context.Background(), "https://issuer.example", "cid"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestNoopStore_WithLockRunsFn(t *testing.T) {
	var s NoopStore
	called := false
	if err := s.WithLock(context.Background(), "https://issuer.example", "cid", func() error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("WithLock: %v", err)
	}
	if !called {
		t.Fatal("WithLock: fn was not invoked")
	}
}
