package hardening

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// MaxClockSkew bounds the distance between the host clock and the forge's.
// Webhook replay protection, delivery freshness and installation-token
// lifetimes all compare timestamps from the forge with the host clock; past
// this skew they refuse or accept the wrong deliveries.
//
// The forge's Date header has a one-second resolution and is truncated, so
// a host in perfect sync reads up to one second behind: 2 s leaves one
// second of real drift.
const MaxClockSkew = 2 * time.Second

// ErrClockSkew is a skew at or beyond MaxClockSkew, or a forge whose clock
// could not be read: an unverifiable clock is not a synchronised one.
var ErrClockSkew = errors.New("clock skew check failed")

// CheckClockSkew returns serverTime - localTime, and fails with ErrClockSkew
// unless its absolute value is below MaxClockSkew.
func CheckClockSkew(serverTime, localTime time.Time) (time.Duration, error) {
	skew := serverTime.Sub(localTime)
	if skew >= MaxClockSkew || skew <= -MaxClockSkew {
		return skew, fmt.Errorf("%w: the forge is %s from this host, limit %s", ErrClockSkew, skew, MaxClockSkew)
	}
	return skew, nil
}

// ProbeClockSkew asks the forge at rawURL (HEAD, no credential, redirects
// not followed: a redirect carries its own Date) and compares the Date
// header of the reply with now(), taken at the middle of the round trip.
// Any status will do. A missing or malformed Date, an unusable URL or a
// failed request fails with ErrClockSkew.
func ProbeClockSkew(ctx context.Context, client *http.Client, rawURL string, now func() time.Time) (time.Duration, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return 0, fmt.Errorf("%w: %q is not an http(s) URL", ErrClockSkew, rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("%w: build request: %w", ErrClockSkew, err)
	}
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	sent := now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrClockSkew, err)
	}
	received := now()
	if err := resp.Body.Close(); err != nil {
		return 0, fmt.Errorf("%w: close reply: %w", ErrClockSkew, err)
	}

	date := resp.Header.Get("Date")
	if date == "" {
		return 0, fmt.Errorf("%w: the reply (status %d) carries no Date header", ErrClockSkew, resp.StatusCode)
	}
	serverTime, err := http.ParseTime(date)
	if err != nil {
		return 0, fmt.Errorf("%w: Date header: %w", ErrClockSkew, err)
	}
	return CheckClockSkew(serverTime, sent.Add(received.Sub(sent)/2))
}
