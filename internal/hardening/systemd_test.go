package hardening

import (
	"context"
	"errors"
	"testing"
)

func showReturning(out string) ShowFunc {
	return func(context.Context, string, ...string) ([]byte, error) { return []byte(out), nil }
}

func TestCheckUnitMemlockAcceptsInfinity(t *testing.T) {
	for _, out := range []string{
		"LimitMEMLOCK=infinity\n",
		"LimitMEMLOCK=18446744073709551615\n",
	} {
		if err := CheckUnitMemlock(context.Background(), showReturning(out), "previewd.service"); err != nil {
			t.Errorf("%q: %v", out, err)
		}
	}
}

// The daemon refuses to start unless RLIMIT_MEMLOCK is unlimited, so a unit
// whose limit is finite, unset or unreadable fails the doctor.
func TestCheckUnitMemlockFailsClosed(t *testing.T) {
	for name, out := range map[string]string{
		"finite":     "LimitMEMLOCK=8388608\n",
		"zero":       "LimitMEMLOCK=0\n",
		"not listed": "LimitNOFILE=524288\n",
		"empty":      "",
		"garbage":    "LimitMEMLOCK infinity\n",
		"blank":      "LimitMEMLOCK=\n",
	} {
		err := CheckUnitMemlock(context.Background(), showReturning(out), "previewd.service")
		if !errors.Is(err, ErrMemlock) {
			t.Errorf("%s: err = %v, want ErrMemlock", name, err)
		}
	}
	show := func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("no systemd") }
	if err := CheckUnitMemlock(context.Background(), show, "previewd.service"); !errors.Is(err, ErrMemlock) {
		t.Errorf("systemd unavailable: err = %v, want ErrMemlock", err)
	}
}

func TestParseShowRefusesNonPropertyLines(t *testing.T) {
	if _, err := parseShow([]byte("A=1\nnot a property\n")); err == nil {
		t.Fatal("a line without '=' was accepted")
	}
	got, err := parseShow([]byte("A=1\n\nB=x=y\nC=\n"))
	if err != nil || got["A"] != "1" || got["B"] != "x=y" || got["C"] != "" || len(got) != 3 {
		t.Fatalf("parseShow = %v, %v", got, err)
	}
}
