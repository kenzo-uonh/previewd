package hardening

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

var skewEpoch = time.Date(2026, time.October, 20, 12, 0, 0, 0, time.UTC)

func TestCheckClockSkew(t *testing.T) {
	for name, tc := range map[string]struct {
		offset time.Duration
		ok     bool
	}{
		"in sync":               {0, true},
		"server ahead, within":  {1900 * time.Millisecond, true},
		"server behind, within": {-1900 * time.Millisecond, true},
		"server ahead, limit":   {MaxClockSkew, false},
		"server behind, limit":  {-MaxClockSkew, false},
		"server far ahead":      {time.Hour, false},
		"server far behind":     {-24 * time.Hour, false},
	} {
		skew, err := CheckClockSkew(skewEpoch.Add(tc.offset), skewEpoch)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrClockSkew) {
			t.Errorf("%s: err %v is not ErrClockSkew", name, err)
		}
		if skew != tc.offset {
			t.Errorf("%s: skew = %v, want %v", name, skew, tc.offset)
		}
	}
}

func dateServer(t *testing.T, date string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if date != "" {
			w.Header()["Date"] = []string{date}
		}
		w.WriteHeader(http.StatusUnauthorized) // a Date header is on any response
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fixedNow(at time.Time) func() time.Time { return func() time.Time { return at } }

func TestProbeClockSkewReadsTheDateHeader(t *testing.T) {
	srv := dateServer(t, skewEpoch.Add(time.Second).Format(http.TimeFormat))
	skew, err := ProbeClockSkew(context.Background(), srv.Client(), srv.URL, fixedNow(skewEpoch))
	if err != nil {
		t.Fatalf("ProbeClockSkew: %v", err)
	}
	if skew != time.Second {
		t.Fatalf("skew = %v, want 1s", skew)
	}
}

func TestProbeClockSkewRefusesADriftedServer(t *testing.T) {
	srv := dateServer(t, skewEpoch.Add(-10*time.Second).Format(http.TimeFormat))
	skew, err := ProbeClockSkew(context.Background(), srv.Client(), srv.URL, fixedNow(skewEpoch))
	if !errors.Is(err, ErrClockSkew) {
		t.Fatalf("err = %v, want ErrClockSkew", err)
	}
	if skew != -10*time.Second {
		t.Fatalf("skew = %v, want -10s (reported even when refused)", skew)
	}
}

// A control that cannot be verified fails: no Date, a Date that is not an
// HTTP date, or a server that does not answer.
func TestProbeClockSkewFailsClosed(t *testing.T) {
	down := httptest.NewServer(http.NotFoundHandler())
	downURL, downClient := down.URL, down.Client()
	down.Close()

	for name, tc := range map[string]struct {
		client *http.Client
		url    string
	}{
		"no Date header":  {nil, dateServer(t, "").URL},
		"malformed Date":  {nil, dateServer(t, "yesterday, around noon").URL},
		"server not up":   {downClient, downURL},
		"not an http URL": {nil, "ftp://example.test/"},
		"unparseable URL": {nil, "http://[::1"},
		"empty URL":       {nil, ""},
	} {
		client := tc.client
		if client == nil {
			client = http.DefaultClient
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := ProbeClockSkew(ctx, client, tc.url, fixedNow(skewEpoch))
		cancel()
		if !errors.Is(err, ErrClockSkew) {
			t.Errorf("%s: err = %v, want ErrClockSkew", name, err)
		}
	}
}

// A redirect is a reply with its own Date: the probe reads it and never
// follows it to a host the operator did not configure.
func TestProbeClockSkewDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Store(true) }))
	t.Cleanup(target.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Date"] = []string{skewEpoch.Format(http.TimeFormat)}
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	if _, err := ProbeClockSkew(context.Background(), srv.Client(), srv.URL, fixedNow(skewEpoch)); err != nil {
		t.Fatalf("ProbeClockSkew: %v", err)
	}
	if followed.Load() {
		t.Fatal("the redirect was followed")
	}
}

func TestProbeClockSkewHonoursCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ProbeClockSkew(ctx, srv.Client(), srv.URL, fixedNow(skewEpoch)); !errors.Is(err, ErrClockSkew) {
		t.Fatalf("err = %v, want ErrClockSkew", err)
	}
}
