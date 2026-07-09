package cache

import "context"

// NoopStore implements Store by persisting nothing: Load always reports a
// clean miss, Save/Delete are no-ops, and WithLock runs fn directly without
// any locking. It backs --token-store=none.
type NoopStore struct{}

var _ Store = (*NoopStore)(nil)

func (NoopStore) Load(ctx context.Context, issuer, clientID string) (Entry, bool, error) {
	return Entry{}, false, nil
}

func (NoopStore) Save(ctx context.Context, e Entry) error {
	return nil
}

func (NoopStore) Delete(ctx context.Context, issuer, clientID string) error {
	return nil
}

func (NoopStore) WithLock(ctx context.Context, issuer, clientID string, fn func() error) error {
	return fn()
}
