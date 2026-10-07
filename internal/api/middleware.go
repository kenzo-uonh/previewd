package api

import (
	"bytes"
	"io"
	"net/http"

	"github.com/kenzo-uonh/previewd/internal/validate"
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
