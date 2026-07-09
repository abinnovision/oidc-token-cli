// Package authflow selects a grant type at runtime (auto|authcode|device-code)
// based on discovery metadata and the local environment, and runs the
// loopback callback server for the authorization-code flow.
package authflow
