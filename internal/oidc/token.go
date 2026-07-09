package oidc

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"

	"github.com/abinnovision/oidc-token-cli/internal/output"
)

// toResult converts an *oauth2.Token response into output.Result. If present,
// the id_token is verified against the issuer's key set; access_tokens are
// never verified. expectedNonce, if non-empty, is additionally checked
// against the id_token's nonce claim (go-oidc's verifier doesn't check
// nonce itself). Only the authcode flow sends a nonce.
//
// A present-but-invalid (or nonce-mismatched) id_token does not fail this
// call: it's recorded on Result.IDTokenError instead, and IDToken is left
// empty. Whether that's fatal depends on --token-type, which this package
// has no visibility into; the runner decides.
func (p *Provider) toResult(ctx context.Context, tok *oauth2.Token, expectedNonce string) (output.Result, error) {
	res := output.Result{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Expiry:       tok.Expiry,
	}

	raw, ok := tok.Extra("id_token").(string)
	if ok && raw != "" {
		idt, err := p.verifier.Verify(ctx, raw)
		switch {
		case err != nil:
			res.IDTokenError = fmt.Errorf("oidc: id_token verification failed: %w", err)
		case expectedNonce != "" && idt.Nonce != expectedNonce:
			res.IDTokenError = fmt.Errorf("oidc: id_token nonce mismatch (possible replay/substitution)")
		default:
			res.IDToken = raw
		}
	}

	return res, nil
}
