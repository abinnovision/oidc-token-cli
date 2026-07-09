// Package cache persists tokens keyed by (issuer, client_id) behind the
// Store interface. Cache is a plaintext-JSON file backend (0600/0700
// permissions, atomic writes, advisory file locking for concurrency-safe
// refresh); KeychainStore persists entries in the OS keychain; ChainStore
// composes backends into a fallback chain (see cache.Backend).
package cache
