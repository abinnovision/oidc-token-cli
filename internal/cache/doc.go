// Package cache persists tokens on disk, keyed by (issuer, client_id), with
// 0600/0700 permissions, atomic writes, and advisory file locking for
// concurrency-safe refresh.
package cache
