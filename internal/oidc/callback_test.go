package oidc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestAwaitCallback_WrongStateDoesNotEndFlow_ThenRealCallbackSucceeds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		code, err := awaitCallback(ctx, ln, "the-real-state")
		resultCh <- result{code, err}
	}()

	// A stray/probe/forged connection with the wrong state must not end
	// the flow: it gets a 4xx, and awaitCallback keeps waiting.
	badResp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?code=bogus&state=wrong-state", port))
	if err != nil {
		t.Fatalf("bogus-state request: %v", err)
	}
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bogus-state request status = %d, want 400", badResp.StatusCode)
	}
	_ = badResp.Body.Close()

	select {
	case res := <-resultCh:
		t.Fatalf("flow ended after a wrong-state request (code=%q err=%v); it must keep listening", res.code, res.err)
	case <-time.After(150 * time.Millisecond):
		// Still waiting, as expected.
	}

	// Now the genuine redirect arrives.
	realResp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?code=the-real-code&state=the-real-state", port))
	if err != nil {
		t.Fatalf("real callback request: %v", err)
	}
	_ = realResp.Body.Close()

	res := <-resultCh
	if res.err != nil {
		t.Fatalf("awaitCallback: %v", res.err)
	}
	if res.code != "the-real-code" {
		t.Fatalf("code = %q, want the-real-code", res.code)
	}
}

func TestAwaitCallback_AuthorizationErrorWithMatchingState_EndsFlow(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		code, err := awaitCallback(ctx, ln, "state-1")
		resultCh <- result{code, err}
	}()

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?error=unauthorized_client&state=state-1", port))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	res := <-resultCh
	if res.err == nil {
		t.Fatal("expected an AuthorizationError")
	}
	var ae *AuthorizationError
	if !errors.As(res.err, &ae) {
		t.Fatalf("err = %v, want *AuthorizationError", res.err)
	}
	if ae.Code != "unauthorized_client" {
		t.Fatalf("Code = %q, want unauthorized_client", ae.Code)
	}
}

func TestAwaitCallback_Timeout_NoRequestEver(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = awaitCallback(ctx, ln, "some-state")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error when nobody ever calls back")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("awaitCallback took %v to give up, want bounded by ctx", elapsed)
	}
}
