//go:build e2e

// Command fakegithub is the GitHub Enterprise Server the E2E suite
// (scripts/verify-e2e.sh) runs previewd against: the GitHub App API subset
// previewd reads, over HTTPS, with a test PKI it generates. A test tool,
// behind the e2e build tag: never part of a previewd build.
//
//	fakegithub init  -dir DIR
//	    writes DIR/ca.pem, ghes.pem, ghes-key.pem (the fake's certificate),
//	    listener.pem, listener-key.pem (previewd's webhook listener) and
//	    app-key.pem (the GitHub App's private key), for 127.0.0.1 and
//	    localhost, valid one day.
//	fakegithub serve -dir DIR -listen 127.0.0.1:18443 -app-id N -installation M
//	    serves the API and the /_fake control endpoints.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if len(os.Args) < 2 {
		logger.Error("usage: fakegithub init|serve [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = initPKI(os.Args[2:])
	case "serve":
		err = serve(os.Args[2:], logger)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		logger.Error("fakegithub failed", "error", err)
		os.Exit(1)
	}
}

func initPKI(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := fs.String("dir", "", "output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("-dir is required")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "previewd E2E test CA"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(*dir, "ca.pem"), "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}
	for i, name := range []string{"ghes", "listener"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i) + 2), Subject: pkix.Name{CommonName: name},
			DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		if err := writePEM(filepath.Join(*dir, name+".pem"), "CERTIFICATE", der, 0o644); err != nil {
			return err
		}
		if err := writePEM(filepath.Join(*dir, name+"-key.pem"), "PRIVATE KEY", keyDER, 0o600); err != nil {
			return err
		}
	}
	appKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	return writePEM(filepath.Join(*dir, "app-key.pem"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(appKey), 0o600)
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

func serve(args []string, logger *slog.Logger) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dir := fs.String("dir", "", "directory written by init")
	listen := fs.String("listen", "127.0.0.1:18443", "listen address (loopback only)")
	appID := fs.Int64("app-id", 0, "GitHub App ID")
	installation := fs.Int64("installation", 0, "the App's installation ID on every repository")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *appID < 1 || *installation < 1 {
		return errors.New("-dir, -app-id and -installation are required")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("-listen %q must be a loopback address", *listen)
	}
	keyPEM, err := os.ReadFile(filepath.Join(*dir, "app-key.pem")) // #nosec G304 -- test tool
	if err != nil {
		return err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return errors.New("app-key.pem: no PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(*dir, "ghes.pem"), filepath.Join(*dir, "ghes-key.pem"))
	if err != nil {
		return err
	}
	g := newGHES(*appID, *installation, &key.PublicKey, logger)
	srv := &http.Server{Addr: *listen, Handler: g.routes(), ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	go func() {
		<-stop
		_ = srv.Close()
	}()
	logger.Info("fakegithub serving", "listen", *listen)
	if err := srv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
