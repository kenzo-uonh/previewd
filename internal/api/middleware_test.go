package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kenzo-uonh/previewd/internal/validate"
)

func signature(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestValidateGitHubSignature(t *testing.T) {
	secret := []byte("s3cret")
	body := []byte(`{"action":"opened"}`)
	big := bytes.Repeat([]byte("x"), validate.MaxPayloadBytes+1)

	cases := []struct {
		name   string
		secret []byte
		body   []byte
		header string
		want   int
	}{
		{"exact signature", secret, body, signature(secret, body), http.StatusOK},
		{"missing header", secret, body, "", http.StatusUnauthorized},
		{"wrong secret", secret, body, signature([]byte("other"), body), http.StatusUnauthorized},
		{"uppercase hex", secret, body, strings.ToUpper(signature(secret, body)), http.StatusUnauthorized},
		{"sha1 prefix", secret, body, strings.Replace(signature(secret, body), "sha256=", "sha1=", 1), http.StatusUnauthorized},
		{"empty secret admits nothing", nil, body, signature(nil, body), http.StatusUnauthorized},
		{"oversized body", secret, big, signature(secret, big), http.StatusRequestEntityTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reached []byte
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				reached = b
			})
			req := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(tc.body))
			if tc.header != "" {
				req.Header.Set(validate.SignatureHeader, tc.header)
			}
			rec := httptest.NewRecorder()
			ValidateGitHubSignature(tc.secret)(next).ServeHTTP(rec, req)

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if tc.want == http.StatusOK && !bytes.Equal(reached, tc.body) {
				t.Fatal("handler did not receive the verified body")
			}
			if tc.want != http.StatusOK && reached != nil {
				t.Fatal("rejected request reached the handler")
			}
		})
	}
}
