package vcs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testAppID    = 31337
	testInstall  = 77
	testToken    = "ghs_TESTONLYtokenvalue0123456789abcdef"
	testHead     = "0123456789abcdef0123456789abcdef01234567"
	testRepo     = "acme/app"
	testOpenerID = 4242
)

var testKey = sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) })

func appKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	k, err := testKey()
	if err != nil {
		t.Fatal(err)
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

// fakeGHES is a GitHub Enterprise Server for one App installation on
// acme/app. Its replies are hooks so each test breaks one thing.
type fakeGHES struct {
	t      *testing.T
	pub    *rsa.PublicKey
	srv    *httptest.Server
	mu     sync.Mutex
	minted []tokenRequest
	calls  []string // method path, token calls only
	// revoked counts DELETE /installation/token with the minted token.
	revoked atomic.Int64

	tokenReply  func() any // the access_tokens reply body
	prReply     func() any
	permReply   func() any
	reviewPages int // pages of reviews; the last one short
	revokeCode  int
	prCode      int
	prRedirect  bool // answer the PR read with a redirect to a valid document
}

func newFakeGHES(t *testing.T) *fakeGHES {
	t.Helper()
	k, _ := appKey(t)
	f := &fakeGHES{t: t, pub: &k.PublicKey, revokeCode: http.StatusNoContent, prCode: http.StatusOK, reviewPages: 1}
	f.tokenReply = func() any {
		return map[string]any{
			"token": testToken, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			"permissions":  map[string]string{"pull_requests": "read", "metadata": "read"},
			"repositories": []map[string]string{{"full_name": testRepo}},
		}
	}
	f.prReply = func() any { return prDoc(testRepo, "open") }
	f.permReply = func() any {
		return map[string]any{"permission": "write", "role_name": "write",
			"user": map[string]any{"login": "opener", "id": testOpenerID, "permissions": map[string]bool{"push": true, "pull": true}}}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/repos/acme/app/installation", func(w http.ResponseWriter, r *http.Request) {
		f.checkJWT(r)
		writeJSON(w, http.StatusOK, map[string]int{"id": testInstall})
	})
	mux.HandleFunc(fmt.Sprintf("POST /api/v3/app/installations/%d/access_tokens", testInstall), func(w http.ResponseWriter, r *http.Request) {
		f.checkJWT(r)
		var req tokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("token request: %v", err)
		}
		f.mu.Lock()
		f.minted = append(f.minted, req)
		f.mu.Unlock()
		writeJSON(w, http.StatusCreated, f.tokenReply())
	})
	mux.HandleFunc("DELETE /api/v3/installation/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+testToken {
			f.revoked.Add(1)
		}
		w.WriteHeader(f.revokeCode)
	})
	mux.HandleFunc("GET /api/v3/repos/acme/app/pulls/7", func(w http.ResponseWriter, r *http.Request) {
		f.checkToken(r)
		if f.prRedirect {
			http.Redirect(w, r, "/api/v3/elsewhere/pulls/7", http.StatusFound)
			return
		}
		writeJSON(w, f.prCode, f.prReply())
	})
	mux.HandleFunc("GET /api/v3/elsewhere/pulls/7", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, f.prReply())
	})
	mux.HandleFunc("GET /api/v3/repos/acme/app/collaborators/{login}/permission", func(w http.ResponseWriter, r *http.Request) {
		f.checkToken(r)
		writeJSON(w, http.StatusOK, f.permReply())
	})
	mux.HandleFunc("GET /api/v3/repos/acme/app/pulls/7/reviews", func(w http.ResponseWriter, r *http.Request) {
		f.checkToken(r)
		page := 0
		if _, err := fmt.Sscanf(r.URL.Query().Get("page"), "%d", &page); err != nil || r.URL.Query().Get("per_page") != "100" {
			t.Errorf("reviews query %q", r.URL.RawQuery)
		}
		n := 0
		switch {
		case page < f.reviewPages:
			n = 100
		case page == f.reviewPages:
			n = 5
		}
		reviews := make([]map[string]any, n)
		for i := range reviews {
			reviews[i] = map[string]any{"id": page*1000 + i + 1, "user": map[string]any{"login": "lead-dev", "id": 7},
				"state": "APPROVED", "commit_id": testHead, "submitted_at": "2026-10-08T12:00:00Z"}
		}
		writeJSON(w, http.StatusOK, reviews)
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func prDoc(base, state string) map[string]any {
	return map[string]any{
		"number": 7, "state": state,
		"head":   map[string]any{"sha": testHead, "repo": map[string]string{"full_name": testRepo}},
		"base":   map[string]any{"repo": map[string]string{"full_name": base}},
		"user":   map[string]any{"login": "opener", "id": testOpenerID},
		"labels": []map[string]string{{"name": "previewd-approved"}},
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// checkJWT verifies the App JWT as GHES does: RS256 over header.claims with
// the App's public key, iss the App ID, iat in the past, exp at most ten
// minutes later.
func (f *fakeGHES) checkJWT(r *http.Request) {
	f.t.Helper()
	jwt, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(jwt, ".")
	if !ok || len(parts) != 3 {
		f.t.Fatalf("no JWT on %s %s", r.Method, r.URL.Path)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		f.t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(f.pub, crypto.SHA256, digest[:], sig); err != nil {
		f.t.Fatalf("JWT signature: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		f.t.Fatal(err)
	}
	var c struct{ IAT, EXP, ISS int64 }
	if err := json.Unmarshal(raw, &c); err != nil {
		f.t.Fatal(err)
	}
	now := time.Now().Unix()
	if c.ISS != testAppID || c.IAT > now || c.EXP <= now || c.EXP-c.IAT > 600 {
		f.t.Fatalf("JWT claims %+v at %d", c, now)
	}
	if r.Header.Get("X-GitHub-Api-Version") == "" || r.Header.Get("Accept") != "application/vnd.github+json" {
		f.t.Fatalf("missing API headers on %s", r.URL.Path)
	}
}

func (f *fakeGHES) checkToken(r *http.Request) {
	f.t.Helper()
	if r.Header.Get("Authorization") != "Bearer "+testToken || strings.Contains(r.URL.String(), testToken) {
		f.t.Fatalf("%s %s: not authenticated by the installation token in the header", r.Method, r.URL)
	}
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
}

func (f *fakeGHES) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
}

func (f *fakeGHES) client(t *testing.T, logs io.Writer) *Client {
	t.Helper()
	_, keyPEM := appKey(t)
	if logs == nil {
		logs = io.Discard
	}
	c, err := NewClient(ClientConfig{BaseURL: f.srv.URL, AppID: testAppID, KeyPEM: keyPEM, CAPEM: f.caPEM(),
		Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPullRequestReadsTruthWithOneScopedTokenRevokedAfterUse(t *testing.T) {
	f := newFakeGHES(t)
	st, err := f.client(t, nil).PullRequest(context.Background(), testRepo, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Open || st.HeadSHA != testHead || st.HeadRepo != testRepo || st.Opener != (Account{Login: "opener", ID: testOpenerID}) ||
		st.OpenerPermission != "write" || len(st.Labels) != 1 || st.Labels[0] != "previewd-approved" {
		t.Fatalf("state = %+v", st)
	}
	if !Trusted(st, testRepo) {
		t.Fatal("same-repository PR opened by a writer is not trusted")
	}
	if len(f.minted) != 1 || len(f.minted[0].Repositories) != 1 || f.minted[0].Repositories[0] != "app" ||
		len(f.minted[0].Permissions) != 1 || f.minted[0].Permissions["pull_requests"] != "read" {
		t.Fatalf("token requests %+v, want one for app with pull_requests:read only", f.minted)
	}
	if f.revoked.Load() != 1 {
		t.Fatalf("token revoked %d times, want 1", f.revoked.Load())
	}
	if want := []string{"GET /api/v3/repos/acme/app/pulls/7", "GET /api/v3/repos/acme/app/collaborators/opener/permission"}; strings.Join(f.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls %v", f.calls)
	}
}

// A fork's opener permission is never read: a fork is never trusted.
func TestPullRequestForkSkipsPermission(t *testing.T) {
	f := newFakeGHES(t)
	f.prReply = func() any {
		d := prDoc(testRepo, "open")
		d["head"] = map[string]any{"sha": testHead, "repo": nil}
		return d
	}
	st, err := f.client(t, nil).PullRequest(context.Background(), testRepo, 7)
	if err != nil || st.HeadRepo != "" || st.OpenerPermission != "" || Trusted(st, testRepo) || len(f.calls) != 1 {
		t.Fatalf("deleted head repo = %+v, %v, calls %v", st, err, f.calls)
	}
}

// Fail closed: a token grant that is not exactly what was asked is revoked
// and refused, and the read fails.
func TestMintRefusesExcessiveGrants(t *testing.T) {
	ok := func() map[string]any {
		return map[string]any{
			"token": testToken, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			"permissions":  map[string]string{"pull_requests": "read", "metadata": "read"},
			"repositories": []map[string]string{{"full_name": testRepo}},
		}
	}
	for name, mutate := range map[string]func(map[string]any){
		"write permission": func(m map[string]any) { m["permissions"] = map[string]string{"pull_requests": "write"} },
		"extra permission": func(m map[string]any) {
			m["permissions"] = map[string]string{"pull_requests": "read", "contents": "read"}
		},
		"no permissions":   func(m map[string]any) { delete(m, "permissions") },
		"all repositories": func(m map[string]any) { delete(m, "repositories") },
		"other repository": func(m map[string]any) { m["repositories"] = []map[string]string{{"full_name": "acme/other"}} },
		"two repositories": func(m map[string]any) {
			m["repositories"] = []map[string]string{{"full_name": testRepo}, {"full_name": "acme/x"}}
		},
		"no expiry":         func(m map[string]any) { delete(m, "expires_at") },
		"expired":           func(m map[string]any) { m["expires_at"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) },
		"three hour expiry": func(m map[string]any) { m["expires_at"] = time.Now().Add(3 * time.Hour).UTC().Format(time.RFC3339) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeGHES(t)
			f.tokenReply = func() any { m := ok(); mutate(m); return m }
			if _, err := f.client(t, nil).PullRequest(context.Background(), testRepo, 7); err == nil {
				t.Fatal("excessive grant accepted")
			}
			if len(f.calls) != 0 || f.revoked.Load() != 1 {
				t.Fatalf("calls %v, revoked %d: want no call and the token revoked", f.calls, f.revoked.Load())
			}
		})
	}
	for name, tok := range map[string]string{"empty": "", "space": "ghs_a b", "newline": "ghs_a\n", "long": strings.Repeat("a", 256)} {
		f := newFakeGHES(t)
		f.tokenReply = func() any { m := ok(); m["token"] = tok; return m }
		if _, err := f.client(t, nil).PullRequest(context.Background(), testRepo, 7); err == nil || len(f.calls) != 0 {
			t.Errorf("token %s accepted (calls %v)", name, f.calls)
		}
	}
}

// Fail closed: an inconsistent reply is an error, and the token is revoked
// on every path.
func TestPullRequestRefusesInconsistentReplies(t *testing.T) {
	for name, tc := range map[string]struct {
		pr   func() any
		perm func() any
		code int
	}{
		"other repository": {pr: func() any { return prDoc("acme/other", "open") }},
		"other number":     {pr: func() any { d := prDoc(testRepo, "open"); d["number"] = 8; return d }},
		"unknown state":    {pr: func() any { return prDoc(testRepo, "merged") }},
		"bad head":         {pr: func() any { d := prDoc(testRepo, "open"); d["head"] = map[string]any{"sha": "beef"}; return d }},
		"no opener":        {pr: func() any { d := prDoc(testRepo, "open"); delete(d, "user"); return d }},
		"bad label":        {pr: func() any { d := prDoc(testRepo, "open"); d["labels"] = []map[string]string{{"name": ""}}; return d }},
		"not found":        {code: http.StatusNotFound},
		"server error":     {code: http.StatusBadGateway},
		"redirect":         {code: http.StatusFound},
		"renamed account": {perm: func() any {
			return map[string]any{"permission": "admin", "user": map[string]any{"login": "opener", "id": 9}}
		}},
		"no account": {perm: func() any { return map[string]any{"permission": "admin"} }},
		"unknown role": {perm: func() any {
			return map[string]any{"permission": "owner", "user": map[string]any{"login": "opener", "id": testOpenerID}}
		}},
		"oversized PR body": {pr: func() any { d := prDoc(testRepo, "open"); d["body"] = strings.Repeat("x", 1<<20); return d }},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeGHES(t)
			if tc.pr != nil {
				f.prReply = tc.pr
			}
			if tc.perm != nil {
				f.permReply = tc.perm
			}
			if tc.code != 0 {
				f.prCode = tc.code
			}
			if st, err := f.client(t, nil).PullRequest(context.Background(), testRepo, 7); err == nil {
				t.Fatalf("accepted %+v", st)
			}
			if f.revoked.Load() != 1 {
				t.Fatalf("token revoked %d times, want 1", f.revoked.Load())
			}
		})
	}
}

// Without write flags, the base role decides; the flags win over the role.
func TestPermissionLevel(t *testing.T) {
	for name, tc := range map[string]struct {
		reply map[string]any
		want  string
	}{
		"flags: maintain": {map[string]any{"permission": "write", "user": map[string]any{"login": "opener", "id": testOpenerID,
			"permissions": map[string]bool{"maintain": true, "push": true}}}, "maintain"},
		"flags: triage over a write role": {map[string]any{"permission": "write", "role_name": "write", "user": map[string]any{"login": "opener", "id": testOpenerID,
			"permissions": map[string]bool{"triage": true, "pull": true}}}, "triage"},
		"flags: none":      {map[string]any{"permission": "admin", "user": map[string]any{"login": "opener", "id": testOpenerID, "permissions": map[string]bool{}}}, "none"},
		"role name":        {map[string]any{"permission": "read", "role_name": "admin", "user": map[string]any{"login": "opener", "id": testOpenerID}}, "admin"},
		"legacy only":      {map[string]any{"permission": "read", "user": map[string]any{"login": "opener", "id": testOpenerID}}, "read"},
		"custom role name": {map[string]any{"permission": "write", "role_name": "deployer", "user": map[string]any{"login": "opener", "id": testOpenerID}}, "write"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeGHES(t)
			f.permReply = func() any { return tc.reply }
			st, err := f.client(t, nil).PullRequest(context.Background(), testRepo, 7)
			if err != nil || st.OpenerPermission != tc.want {
				t.Fatalf("permission = %q, %v; want %q", st.OpenerPermission, err, tc.want)
			}
		})
	}
}

// A failed revocation is logged by repository and expiry, never with the
// token, and does not fail a completed read.
func TestRevocationFailureLoggedWithoutToken(t *testing.T) {
	f := newFakeGHES(t)
	f.revokeCode = http.StatusInternalServerError
	var logs bytes.Buffer
	if _, err := f.client(t, &logs).PullRequest(context.Background(), testRepo, 7); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "Could not revoke") || strings.Contains(logs.String(), testToken) {
		t.Fatalf("log %q", logs.String())
	}
}

// No error string carries the token, even when a reply quotes it.
func TestErrorsNeverCarryTheToken(t *testing.T) {
	f := newFakeGHES(t)
	f.prCode = http.StatusForbidden
	f.prReply = func() any { return map[string]string{"message": "bad credentials"} }
	_, err := f.client(t, nil).PullRequest(context.Background(), testRepo, 7)
	if err == nil || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "Bearer") {
		t.Fatalf("error %v", err)
	}
}

// No redirect is followed: a PR read answered 302 fails, even toward a
// valid document on the same host.
func TestClientFollowsNoRedirect(t *testing.T) {
	f := newFakeGHES(t)
	f.prRedirect = true
	if st, err := f.client(t, nil).PullRequest(context.Background(), testRepo, 7); err == nil {
		t.Fatalf("redirect followed: %+v", st)
	}
}

// The transport never takes a proxy from the environment (structural: Go
// never proxies loopback, so the behavioral test below cannot see it), and
// the site CA bundle is the whole trust: not added to the system roots.
func TestClientTransportPolicy(t *testing.T) {
	f := newFakeGHES(t)
	tr := f.client(t, nil).http.Transport.(*http.Transport)
	if tr.Proxy != nil || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("transport: proxy set %v, min TLS %x", tr.Proxy != nil, tr.TLSClientConfig.MinVersion)
	}
	only := x509.NewCertPool()
	only.AddCert(f.srv.Certificate())
	got, err := CertPool(f.caPEM())
	if err != nil || !got.Equal(only) || !tr.TLSClientConfig.RootCAs.Equal(only) {
		t.Fatalf("the CA pool is not exactly the bundle (%v)", err)
	}
}

// Proxy: nil. With HTTPS_PROXY set, no request reaches the proxy.
func TestClientIgnoresProxyFromEnvironment(t *testing.T) {
	var proxied atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	f := newFakeGHES(t)
	if _, err := f.client(t, nil).PullRequest(context.Background(), testRepo, 7); err != nil {
		t.Fatal(err)
	}
	if proxied.Load() != 0 {
		t.Fatalf("%d requests reached the proxy", proxied.Load())
	}
}

// The site CA, and only it: without it the GHES certificate does not verify.
func TestClientTrustsOnlyTheConfiguredCA(t *testing.T) {
	f := newFakeGHES(t)
	_, keyPEM := appKey(t)
	// httptest servers share one certificate: mint a distinct CA.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	otherCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for name, ca := range map[string][]byte{"system roots": nil, "another CA": otherCA} {
		c, err := NewClient(ClientConfig{BaseURL: f.srv.URL, AppID: testAppID, KeyPEM: keyPEM, CAPEM: ca})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.PullRequest(context.Background(), testRepo, 7); err == nil || len(f.minted) != 0 {
			t.Fatalf("%s: GHES certificate accepted", name)
		}
	}
}

func TestReviewsPaginationIsBounded(t *testing.T) {
	f := newFakeGHES(t)
	f.reviewPages = 2
	reviews, err := f.client(t, nil).Reviews(context.Background(), testRepo, 7)
	if err != nil || len(reviews) != 105 || reviews[0].User != (Account{Login: "lead-dev", ID: 7}) || reviews[0].State != "APPROVED" {
		t.Fatalf("reviews = %d, %v", len(reviews), err)
	}
	if f.revoked.Load() != 1 {
		t.Fatalf("revoked %d", f.revoked.Load())
	}
	f = newFakeGHES(t)
	f.reviewPages = 11
	if _, err := f.client(t, nil).Reviews(context.Background(), testRepo, 7); err == nil {
		t.Fatal("more than 1,000 reviews accepted as a partial list")
	}
	if f.revoked.Load() != 1 {
		t.Fatalf("revoked %d after a refused list", f.revoked.Load())
	}
}

// The signing input is fixed (golden), and the signature verifies.
func TestJWTGolden(t *testing.T) {
	k, _ := appKey(t)
	iat := time.Unix(1791460800, 0)
	jwt, err := signJWT(k, testAppID, iat, iat.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	const want = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3OTE0NjA4MDAsImV4cCI6MTc5MTQ2MTQwMCwiaXNzIjozMTMzN30"
	head, sig, _ := strings.Cut(jwt[len(want):], ".")
	if !strings.HasPrefix(jwt, want+".") || head != "" {
		t.Fatalf("signing input %q, want %q", jwt[:len(want)], want)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(want))
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, digest[:], raw); err != nil {
		t.Fatal(err)
	}
}

func TestNewClientRefusesBadKeysAndBundles(t *testing.T) {
	_, keyPEM := appKey(t)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeGHES(t)
	for name, cfg := range map[string]ClientConfig{
		"no key":        {AppID: 1},
		"weak key":      {AppID: 1, KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)})},
		"EC key":        {AppID: 1, KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER})},
		"two keys":      {AppID: 1, KeyPEM: append(append([]byte{}, keyPEM...), keyPEM...)},
		"no app id":     {KeyPEM: keyPEM},
		"key as CA":     {AppID: 1, KeyPEM: keyPEM, CAPEM: keyPEM},
		"CA with key":   {AppID: 1, KeyPEM: keyPEM, CAPEM: append(f.caPEM(), keyPEM...)},
		"CA with junk":  {AppID: 1, KeyPEM: keyPEM, CAPEM: append(f.caPEM(), "junk"...)},
		"empty CA file": {AppID: 1, KeyPEM: keyPEM, CAPEM: []byte{}},
	} {
		cfg.BaseURL = "https://ghes.corp"
		if _, err := NewClient(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Untrusted names never reach a URL path unvalidated.
func TestPullRequestRefusesInvalidNames(t *testing.T) {
	f := newFakeGHES(t)
	c := f.client(t, nil)
	for _, repo := range []string{"acme/../x", "acme", "acme/app/pulls", "a b/c"} {
		if _, err := c.PullRequest(context.Background(), repo, 7); err == nil {
			t.Errorf("repository %q accepted", repo)
		}
	}
	if _, err := c.PullRequest(context.Background(), testRepo, 0); err == nil {
		t.Error("PR 0 accepted")
	}
	if len(f.minted) != 0 {
		t.Fatalf("tokens minted for invalid names: %d", len(f.minted))
	}
}

// metadataToken is the access_tokens reply of a metadata:read token.
func metadataToken() any {
	return map[string]any{
		"token": testToken, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"permissions":  map[string]string{"metadata": "read"},
		"repositories": []map[string]string{{"full_name": testRepo}},
	}
}

// An approver's permission is read by the login GHES reports now, with a
// metadata:read token revoked after use, and only for the same account ID:
// a renamed approver is still found by ID, and a login taken over by another
// account is refused with ErrAccountMismatch.
func TestPermissionIsReadForTheSameAccountID(t *testing.T) {
	f := newFakeGHES(t)
	f.tokenReply = metadataToken
	f.permReply = func() any {
		return map[string]any{"permission": "admin", "role_name": "admin",
			"user": map[string]any{"login": "lead-dev-renamed", "id": 7, "permissions": map[string]bool{"admin": true, "push": true, "pull": true}}}
	}
	c := f.client(t, nil)
	level, err := c.Permission(context.Background(), testRepo, Account{Login: "lead-dev-renamed", ID: 7})
	if err != nil || level != "admin" {
		t.Fatalf("Permission = %q, %v", level, err)
	}
	if len(f.minted) != 1 || len(f.minted[0].Permissions) != 1 || f.minted[0].Permissions["metadata"] != "read" {
		t.Fatalf("token requests %+v, want one with metadata:read only", f.minted)
	}
	if f.revoked.Load() != 1 || strings.Join(f.calls, ",") != "GET /api/v3/repos/acme/app/collaborators/lead-dev-renamed/permission" {
		t.Fatalf("revoked %d, calls %v", f.revoked.Load(), f.calls)
	}

	// The login now belongs to account 99: never account 7's permission.
	f.permReply = func() any {
		return map[string]any{"permission": "admin", "role_name": "admin",
			"user": map[string]any{"login": "lead-dev", "id": 99, "permissions": map[string]bool{"admin": true}}}
	}
	if level, err := c.Permission(context.Background(), testRepo, Account{Login: "lead-dev", ID: 7}); !errors.Is(err, ErrAccountMismatch) || level != "" {
		t.Fatalf("taken-over login = %q, %v; want ErrAccountMismatch", level, err)
	}
	if f.revoked.Load() != 2 {
		t.Fatalf("token revoked %d times after two reads, want 2", f.revoked.Load())
	}

	// An invalid account is refused before any token is minted.
	for _, who := range []Account{{Login: "", ID: 7}, {Login: "lead-dev", ID: 0}, {Login: "../admin", ID: 7}} {
		if _, err := c.Permission(context.Background(), testRepo, who); err == nil {
			t.Errorf("Permission(%+v) accepted", who)
		}
	}
	if len(f.minted) != 2 {
		t.Fatalf("%d tokens minted, want 2: an invalid account must not reach GHES", len(f.minted))
	}
}
