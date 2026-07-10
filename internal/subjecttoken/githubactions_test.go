package subjecttoken

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeGetenv(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

func TestFetchGitHubActions_Success(t *testing.T) {
	var gotAuth, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":"jwt-abc","count":1}`))
	}))
	defer srv.Close()

	getenv := fakeGetenv(map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL":   srv.URL + "?existing=1",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token",
	})

	token, err := FetchGitHubActions(context.Background(), getenv, "gtb-abinnovision", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "jwt-abc" {
		t.Fatalf("token = %q, want %q", token, "jwt-abc")
	}
	if gotAuth != "bearer req-token" {
		t.Fatalf("Authorization header = %q, want %q", gotAuth, "bearer req-token")
	}
	if !strings.Contains(gotQuery, "audience=gtb-abinnovision") {
		t.Fatalf("query = %q, want it to contain audience=gtb-abinnovision", gotQuery)
	}
}

func TestFetchGitHubActions_AudienceOmittedWhenEmpty(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"value":"jwt-abc"}`))
	}))
	defer srv.Close()

	getenv := fakeGetenv(map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL":   srv.URL,
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token",
	})

	if _, err := FetchGitHubActions(context.Background(), getenv, "", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(gotQuery, "audience=") {
		t.Fatalf("query = %q, want no audience param", gotQuery)
	}
}

func TestFetchGitHubActions_MissingEnvVars(t *testing.T) {
	tests := map[string]map[string]string{
		"both missing": {},
		"missing url":  {"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token"},
		"missing token": {
			"ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.com",
		},
	}
	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			called := false
			httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				called = true
				return nil, nil
			})}

			_, err := FetchGitHubActions(context.Background(), fakeGetenv(values), "aud", httpClient)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), "id-token: write") {
				t.Fatalf("error = %q, want it to mention id-token: write", err)
			}
			if called {
				t.Fatal("expected no HTTP call to be made")
			}
		})
	}
}

func TestFetchGitHubActions_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	getenv := fakeGetenv(map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL":   srv.URL,
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token",
	})

	_, err := FetchGitHubActions(context.Background(), getenv, "aud", nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("error = %q, want it to mention the status code", err)
	}
}

func TestFetchGitHubActions_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	getenv := fakeGetenv(map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL":   srv.URL,
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token",
	})

	if _, err := FetchGitHubActions(context.Background(), getenv, "aud", nil); err == nil {
		t.Fatal("expected an error")
	}
}

func TestFetchGitHubActions_EmptyValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":""}`))
	}))
	defer srv.Close()

	getenv := fakeGetenv(map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL":   srv.URL,
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token",
	})

	if _, err := FetchGitHubActions(context.Background(), getenv, "aud", nil); err == nil {
		t.Fatal("expected an error")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
