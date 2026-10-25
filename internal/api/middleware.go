package api

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"github.com/kenzo-uonh/previewd/internal/validate"
	"github.com/kenzo-uonh/previewd/internal/vcs"
)

// ValidateGitHubSignature admits a request only if its body, read up to
// validate.MaxPayloadBytes, carries the exact HMAC-SHA256 signature for
// secret. An empty secret admits nothing: there is no unauthenticated mode.
func ValidateGitHubSignature(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(io.LimitReader(r.Body, validate.MaxPayloadBytes+1))
			if err != nil {
				http.Error(w, "payload read failure", http.StatusBadRequest)
				return
			}
			if len(body) > validate.MaxPayloadBytes {
				http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
				return
			}

			if err := validate.VerifySignature(secret, body, r.Header.Get(validate.SignatureHeader)); err != nil {
				http.Error(w, "invalid signature", http.StatusUnauthorized)
				return
			}

			// Restore the verified body for the handler.
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}
}

// VerifyWebhook admits a request only if the forge driver p authenticates it
// against secret, and hands the handler its verified body. An empty secret
// admits nothing: there is no unauthenticated mode. The reply never says
// why a request was refused beyond the status, and never carries the secret
// or the token it was given.
func VerifyWebhook(p vcs.Provider, secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := p.VerifyWebhook(r, secret)
			switch {
			case errors.Is(err, validate.ErrSignature):
				http.Error(w, "invalid signature", http.StatusUnauthorized)
				return
			case errors.Is(err, vcs.ErrBodyTooLarge):
				http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
				return
			case err != nil:
				http.Error(w, "payload read failure", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}
}
