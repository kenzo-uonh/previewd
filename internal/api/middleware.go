package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
)

// ValidateGitHubSignature verifies incoming HMAC-SHA256 signatures via constant-time comparison.
func ValidateGitHubSignature(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if secret == "" {
				next.ServeHTTP(w, r)
				return
			}

			sigHeader := r.Header.Get("X-Hub-Signature-256")
			if sigHeader == "" {
				http.Error(w, "missing signature", http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(sigHeader, "=", 2)
			if len(parts) != 2 || parts[0] != "sha256" {
				http.Error(w, "malformed signature header", http.StatusUnauthorized)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "payload read failure", http.StatusBadRequest)
				return
			}

			// Restore request body for downstream JSON decoding
			r.Body = io.NopCloser(bytes.NewBuffer(body))

			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(body)
			expectedMAC := hex.EncodeToString(mac.Sum(nil))

			if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expectedMAC)) != 1 {
				http.Error(w, "invalid cryptographic signature", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
