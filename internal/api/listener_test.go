package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testPKI is a CA and leaf certificates for 127.0.0.1 it signs.
type testPKI struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
	serial int64
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testPKI{ca: ca, caKey: key, caPEM: pemBlock("CERTIFICATE", der), serial: 1}
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// leaf writes a certificate for 127.0.0.1 valid [from, to] and its key into
// dir, and returns their paths and the serial.
func (p *testPKI) leaf(t *testing.T, dir string, from, to time.Time) (certFile, keyFile string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(p.serial), Subject: pkix.Name{CommonName: "previewd"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: from, NotAfter: to,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pemBlock("CERTIFICATE", der), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pemBlock("PRIVATE KEY", keyDER), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, p.serial
}

func keyFrom(path string) func() ([]byte, error) {
	return func() ([]byte, error) { return os.ReadFile(path) } // #nosec G304 -- test file
}

// serveTLS serves h with the listener policy on 127.0.0.1 and returns its
// address.
func serveTLS(t *testing.T, r *CertReloader, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, TLSConfig: TLSConfig(r), ReadHeaderTimeout: time.Second, ErrorLog: nil}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func tlsClient(caPEM []byte, mutate func(*tls.Config)) *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS10} // #nosec G402 -- the test probes the server's floor
	if mutate != nil {
		mutate(cfg)
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, Proxy: nil, DisableKeepAlives: true}}
}

func servedSerial(t *testing.T, c *http.Client, addr string) int64 {
	t.Helper()
	resp, err := c.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.TLS.PeerCertificates[0].SerialNumber.Int64()
}

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

// TLS 1.2 or later with AEAD suites; plaintext HTTP is not served.
func TestListenerTLSPolicy(t *testing.T) {
	pki := newTestPKI(t)
	cert, key, serial := pki.leaf(t, t.TempDir(), time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	r, err := NewCertReloader(cert, keyFrom(key))
	if err != nil {
		t.Fatal(err)
	}
	if cfg := TLSConfig(r); cfg.MinVersion != tls.VersionTLS12 || len(cfg.CipherSuites) == 0 {
		t.Fatalf("policy: min %x, %d suites", cfg.MinVersion, len(cfg.CipherSuites))
	}
	addr := serveTLS(t, r, okHandler)
	if got := servedSerial(t, tlsClient(pki.caPEM, nil), addr); got != serial {
		t.Fatalf("served serial %d, want %d", got, serial)
	}
	for name, mutate := range map[string]func(*tls.Config){
		"TLS 1.1": func(c *tls.Config) { c.MaxVersion = tls.VersionTLS11 },
		"CBC suite on TLS 1.2": func(c *tls.Config) {
			c.MaxVersion = tls.VersionTLS12
			c.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
		},
	} {
		if resp, err := tlsClient(pki.caPEM, mutate).Get("https://" + addr + "/"); err == nil {
			_ = resp.Body.Close()
			t.Errorf("%s: handshake accepted", name)
		}
	}
	if resp, err := tlsClient(pki.caPEM, func(c *tls.Config) { c.RootCAs = x509.NewCertPool() }).Get("https://" + addr + "/"); err == nil {
		_ = resp.Body.Close()
		t.Error("certificate verified without its CA")
	}
	// A plaintext request on the TLS port is answered 400 by the TLS stack,
	// never routed.
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Post("http://"+addr+"/webhooks/github", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "HTTPS") {
		t.Fatalf("plaintext request: %d %q", resp.StatusCode, body)
	}
}

// SIGHUP: a reload serves the new pair to new connections; a failed reload
// keeps the pair in use.
func TestCertReloaderReload(t *testing.T) {
	pki := newTestPKI(t)
	dir := t.TempDir()
	cert, key, first := pki.leaf(t, dir, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	r, err := NewCertReloader(cert, keyFrom(key))
	if err != nil {
		t.Fatal(err)
	}
	addr := serveTLS(t, r, okHandler)
	c := tlsClient(pki.caPEM, nil)
	if got := servedSerial(t, c, addr); got != first {
		t.Fatalf("serial %d, want %d", got, first)
	}
	_, _, second := pki.leaf(t, dir, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := servedSerial(t, c, addr); got != second {
		t.Fatalf("after reload serial %d, want %d", got, second)
	}
	if err := os.WriteFile(cert, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.Reload(); err == nil {
		t.Fatal("reload of a broken certificate accepted")
	}
	if got := servedSerial(t, c, addr); got != second {
		t.Fatalf("after a failed reload serial %d, want %d kept", got, second)
	}
	if err := os.Remove(cert); err != nil {
		t.Fatal(err)
	}
	if err := r.Reload(); err == nil {
		t.Fatal("reload of a removed certificate accepted")
	}
	if got := servedSerial(t, c, addr); got != second {
		t.Fatalf("after a failed read serial %d, want %d kept", got, second)
	}
}

// Fail closed: a pair that is missing, mismatched, expired, not yet valid
// or oversized refuses to start.
func TestNewCertReloaderRefusesBadPairs(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()
	okCert, okKey, _ := pki.leaf(t, t.TempDir(), now.Add(-time.Minute), now.Add(time.Hour))
	_, otherKey, _ := pki.leaf(t, t.TempDir(), now.Add(-time.Minute), now.Add(time.Hour))
	expiredCert, expiredKey, _ := pki.leaf(t, t.TempDir(), now.Add(-2*time.Hour), now.Add(-time.Hour))
	futureCert, futureKey, _ := pki.leaf(t, t.TempDir(), now.Add(time.Hour), now.Add(2*time.Hour))
	big := filepath.Join(t.TempDir(), "big.pem")
	if err := os.WriteFile(big, make([]byte, maxCertFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		cert string
		key  func() ([]byte, error)
	}{
		"missing certificate": {filepath.Join(t.TempDir(), "none.pem"), keyFrom(okKey)},
		"missing key":         {okCert, func() ([]byte, error) { return nil, errors.New("no credential") }},
		"mismatched key":      {okCert, keyFrom(otherKey)},
		"expired":             {expiredCert, keyFrom(expiredKey)},
		"not yet valid":       {futureCert, keyFrom(futureKey)},
		"oversized chain":     {big, keyFrom(okKey)},
	} {
		if _, err := NewCertReloader(tc.cert, tc.key); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// countingBody counts reads: the filter must refuse before any.
type countingBody struct{ reads atomic.Int64 }

func (b *countingBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	return len(p), nil
}

func (b *countingBody) Close() error { return nil }

// The source filter answers 403 before the body is read, even a body larger
// than the cap; an allowed peer (IPv4-mapped IPv6 included) passes.
func TestSourceFilter(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd00::/8")}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reached := 0
	h := SourceFilter(allowed, logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.WriteHeader(http.StatusAccepted)
	}))
	for addr, want := range map[string]int{
		"10.20.3.4:5000":          http.StatusAccepted,
		"[::ffff:10.20.3.4]:5000": http.StatusAccepted,
		"[fd00::1]:5000":          http.StatusAccepted,
		"10.21.0.1:5000":          http.StatusForbidden,
		"127.0.0.1:5000":          http.StatusForbidden,
		"[::1]:5000":              http.StatusForbidden,
		"not-an-address":          http.StatusForbidden,
	} {
		body := &countingBody{}
		req := httptest.NewRequest(http.MethodPost, "/webhooks/github", nil)
		req.Body, req.ContentLength, req.RemoteAddr = body, 2<<20, addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", addr, rec.Code, want)
		}
		if want == http.StatusForbidden && body.reads.Load() != 0 {
			t.Errorf("%s: body read %d times before the refusal", addr, body.reads.Load())
		}
	}
	if reached != 3 {
		t.Fatalf("handler reached %d times, want 3", reached)
	}
	if h := SourceFilter(nil, logger)(okHandler); h == nil {
		t.Fatal("no prefixes: nil handler")
	}
}
