package api

// The webhook listener (V1 spec C2, V1-I8): TLS 1.2 or later with AEAD
// cipher suites only, a certificate re-read on SIGHUP, and a source filter
// that refuses a peer outside the allowed CIDRs before the body is read.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"sync/atomic"
	"time"
)

// maxCertFileBytes bounds the certificate chain file.
const maxCertFileBytes = 64 << 10

// aeadSuites are the TLS 1.2 suites allowed: ECDHE key exchange and AEAD
// only. TLS 1.3 suites are all AEAD and not configurable.
func aeadSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

// CertReloader holds the listener's certificate. The chain comes from a
// file (PREVIEWD_TLS_CERT_FILE); the private key from loadKey, which reads
// the systemd credential (never a file on persistent disk).
type CertReloader struct {
	certFile string
	loadKey  func() ([]byte, error)
	now      func() time.Time
	cur      atomic.Pointer[tls.Certificate]
}

// NewCertReloader loads the pair once. A missing, mismatched, expired or
// not yet valid pair refuses to start.
func NewCertReloader(certFile string, loadKey func() ([]byte, error)) (*CertReloader, error) {
	r := &CertReloader{certFile: certFile, loadKey: loadKey, now: time.Now}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload re-reads the pair (SIGHUP). On any failure the certificate in use
// stays, and the error says why.
func (r *CertReloader) Reload() error {
	chain, err := readBounded(r.certFile, maxCertFileBytes)
	if err != nil {
		return fmt.Errorf("listener certificate: %w", err)
	}
	key, err := r.loadKey()
	if err != nil {
		return fmt.Errorf("listener key: %w", err)
	}
	pair, err := tls.X509KeyPair(chain, key)
	clear(key)
	if err != nil {
		return fmt.Errorf("listener certificate and key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("listener certificate: %w", err)
	}
	if now := r.now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("listener certificate is valid from %s to %s, not now", leaf.NotBefore.UTC().Format(time.RFC3339),
			leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	pair.Leaf = leaf
	r.cur.Store(&pair)
	return nil
}

// Leaf returns the certificate in use.
func (r *CertReloader) Leaf() *x509.Certificate { return r.cur.Load().Leaf }

// TLSConfig is the listener policy: TLS 1.2 or later, AEAD suites, the
// reloadable certificate. No client certificate is asked: GHES
// authenticates with the HMAC signature.
func TLSConfig(r *CertReloader) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CipherSuites:     aeadSuites(),
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		GetCertificate:   func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return r.cur.Load(), nil },
	}
}

// SourceFilter refuses, with 403 and before the body is read, a peer whose
// address is not in allowed (PREVIEWD_WEBHOOK_ALLOWED_CIDRS). No prefix
// allows every source. The peer is the TCP peer: no forwarding header is
// believed.
func SourceFilter(allowed []netip.Prefix, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if len(allowed) == 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer, err := netip.ParseAddrPort(r.RemoteAddr)
			if err == nil && contains(allowed, peer.Addr().Unmap()) {
				next.ServeHTTP(w, r)
				return
			}
			logger.Error("Webhook refused: source outside PREVIEWD_WEBHOOK_ALLOWED_CIDRS", "remote_addr", r.RemoteAddr)
			// Close the connection: the unread body is never consumed.
			w.Header().Set("Connection", "close")
			http.Error(w, "source not allowed", http.StatusForbidden)
		})
	}
}

func contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func readBounded(path string, limit int64) (data []byte, err error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's PREVIEWD_TLS_CERT_FILE
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close %s: %w", path, closeErr))
		}
	}()
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return data, nil
}
