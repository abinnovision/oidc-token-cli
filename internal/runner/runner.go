package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/abinnovision/oidc-token-cli/internal/cache"
	"github.com/abinnovision/oidc-token-cli/internal/config"
	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// Skew is subtracted from a cached token's expiry so a token doesn't expire
// mid-flight between the check and the caller actually using it.
const Skew = 30 * time.Second

// refreshTimeout bounds a single silent-refresh attempt since it runs while
// holding the profile lock, blocking any concurrent caller waiting on it.
const refreshTimeout = 30 * time.Second

// Sentinel errors so callers (and tests) can distinguish failure classes via
// errors.Is; all are wrapped with fmt.Errorf %w.
var (
	// ErrLoginFailed wraps a failure from TokenSource.Login.
	ErrLoginFailed = errors.New("interactive login failed")
	// ErrRefreshFailed wraps a failure from TokenSource.Refresh.
	ErrRefreshFailed = errors.New("token refresh failed")
	// ErrCacheRead wraps a non-miss cache I/O error (e.g. permission denied).
	ErrCacheRead = errors.New("cache read failed")
	// ErrCacheWrite wraps a failure persisting a new/refreshed token.
	ErrCacheWrite = errors.New("cache write failed")
	// ErrIDTokenInvalid wraps an id_token verification failure that is
	// fatal; see checkIDToken.
	ErrIDTokenInvalid = errors.New("id_token verification failed")
)

// TokenSource performs the network-facing parts of minting a token.
type TokenSource interface {
	// Refresh silently exchanges a refresh token for a new token set; it
	// must not perform any interactive step.
	Refresh(ctx context.Context, refreshToken string) (output.Result, error)
	// Login performs whatever interactive flow the configured grant type
	// requires. --non-interactive means "the terminal is unattended", not
	// "never call Login": an authcode+browser flow may still be viable
	// with no TTY (e.g. frpc's exec context with a desktop session).
	// Login's implementation decides which grants that rules out.
	Login(ctx context.Context) (output.Result, error)
}

// Runner orchestrates: cache hit -> silent refresh (locked) -> interactive
// login, in that order, stopping at the first step that yields a usable
// token.
type Runner struct {
	Cache  cache.Store
	Source TokenSource
	Config *config.Config
	// Now is injected for deterministic expiry tests; defaults to time.Now.
	Now func() time.Time
	// Stderr receives non-fatal warnings (e.g. missing refresh_token).
	// Never receives token material.
	Stderr io.Writer
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Run resolves a token for r.Config.Issuer/ClientID, trying the cache,
// then a locked silent refresh, then (unless forbidden) interactive login.
func (r *Runner) Run(ctx context.Context) (output.Result, error) {
	issuer, clientID := r.Config.Issuer, r.Config.ClientID

	entry, ok, err := r.Cache.Load(ctx, issuer, clientID)
	if err != nil {
		return output.Result{}, fmt.Errorf("%w: %w", ErrCacheRead, err)
	}

	if ok && r.entryValid(entry) {
		return entryResult(entry), nil
	}

	if ok && entry.RefreshToken != "" {
		result, refreshErr := r.tryRefresh(ctx, issuer, clientID, entry)
		if refreshErr == nil {
			return result, nil
		}
		// Fall through to interactive login on refresh failure.
	}

	return r.login(ctx, issuer, clientID)
}

func (r *Runner) entryValid(e cache.Entry) bool {
	if e.AccessToken == "" && e.IDToken == "" {
		return false
	}
	if e.Expiry.IsZero() {
		// No expiry info: treat as invalid to trigger a refresh, unless
		// there's no refresh_token, in which case this is all we have.
		return e.RefreshToken == ""
	}
	return r.now().Before(e.Expiry.Add(-Skew))
}

// tryRefresh runs the read -> refresh -> write critical section under the
// profile's flock, re-reading first in case a concurrent winner already
// refreshed successfully.
func (r *Runner) tryRefresh(ctx context.Context, issuer, clientID string, staleEntry cache.Entry) (output.Result, error) {
	var (
		result output.Result
		outErr error
	)
	lockErr := r.Cache.WithLock(ctx, issuer, clientID, func() error {
		fresh, ok, err := r.Cache.Load(ctx, issuer, clientID)
		if err == nil && ok && r.entryValid(fresh) {
			result = entryResult(fresh)
			return nil
		}

		refreshToken := staleEntry.RefreshToken
		if ok {
			refreshToken = fresh.RefreshToken
		}
		if refreshToken == "" {
			outErr = fmt.Errorf("%w: no refresh_token available", ErrRefreshFailed)
			return nil
		}

		refreshCtx, cancel := context.WithTimeout(ctx, refreshTimeout)
		defer cancel()
		res, err := r.Source.Refresh(refreshCtx, refreshToken)
		if err != nil {
			outErr = fmt.Errorf("%w: %w", ErrRefreshFailed, err)
			return nil
		}
		if err := r.checkIDToken(res); err != nil {
			outErr = err
			return nil
		}
		if res.RefreshToken == "" {
			// IdP may omit refresh_token without actually rotating/revoking it.
			res.RefreshToken = refreshToken
		}
		if err := r.persist(ctx, issuer, clientID, res); err != nil {
			outErr = fmt.Errorf("%w: %w", ErrCacheWrite, err)
			return nil
		}
		result = res
		return nil
	})
	if lockErr != nil {
		return output.Result{}, lockErr
	}
	if outErr != nil {
		return output.Result{}, outErr
	}
	return result, nil
}

func (r *Runner) login(ctx context.Context, issuer, clientID string) (output.Result, error) {
	res, err := r.Source.Login(ctx)
	if err != nil {
		return output.Result{}, fmt.Errorf("%w: %w", ErrLoginFailed, err)
	}
	if err := r.checkIDToken(res); err != nil {
		return output.Result{}, err
	}
	if res.RefreshToken == "" && r.Stderr != nil {
		fmt.Fprintln(r.Stderr, "warning: issuer did not return a refresh_token; silent refresh will not be possible for this profile")
	}
	if err := r.persist(ctx, issuer, clientID, res); err != nil {
		return output.Result{}, fmt.Errorf("%w: %w", ErrCacheWrite, err)
	}
	return res, nil
}

// checkIDToken treats a failed id_token verification as fatal only when the
// caller selected --token-type=id_token; otherwise it's a stderr warning.
func (r *Runner) checkIDToken(res output.Result) error {
	if res.IDTokenError == nil {
		return nil
	}
	if r.Config.TokenType == config.TokenTypeIDToken {
		return fmt.Errorf("%w: %w", ErrIDTokenInvalid, res.IDTokenError)
	}
	if r.Stderr != nil {
		fmt.Fprintf(r.Stderr, "warning: id_token verification failed (%v); continuing since --token-type=%s was requested\n", res.IDTokenError, r.Config.TokenType)
	}
	return nil
}

// Logout removes any cached entry for r.Config.Issuer/ClientID.
func (r *Runner) Logout(ctx context.Context) error {
	return r.Cache.Delete(ctx, r.Config.Issuer, r.Config.ClientID)
}

func (r *Runner) persist(ctx context.Context, issuer, clientID string, res output.Result) error {
	return r.Cache.Save(ctx, cache.Entry{
		Issuer:       issuer,
		ClientID:     clientID,
		AccessToken:  res.AccessToken,
		IDToken:      res.IDToken,
		RefreshToken: res.RefreshToken,
		Expiry:       res.Expiry,
	})
}

func entryResult(e cache.Entry) output.Result {
	return output.Result{
		AccessToken:  e.AccessToken,
		IDToken:      e.IDToken,
		RefreshToken: e.RefreshToken,
		Expiry:       e.Expiry,
	}
}
