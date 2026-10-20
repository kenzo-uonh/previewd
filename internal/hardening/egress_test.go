package hardening

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const goodShow = "IPAddressDeny=0.0.0.0/0 ::/0\n" +
	"IPAddressAllow=127.0.0.0/8 ::1/128 172.30.255.0/24\n" +
	"NeedDaemonReload=no\n"

func TestCheckEgressFilterAccepts(t *testing.T) {
	for name, show := range map[string]string{
		"deny all, loopback and proxy allowed": goodShow,
		"deny spelled any":                     "IPAddressDeny=any\nIPAddressAllow=127.0.0.0/8 ::1/128\nNeedDaemonReload=no\n",
		"nothing allowed":                      "IPAddressDeny=0.0.0.0/0 ::/0\nIPAddressAllow=\nNeedDaemonReload=no\n",
		"reload state not asked":               "IPAddressDeny=0.0.0.0/0 ::/0\nIPAddressAllow=127.0.0.0/8\n",
		"a narrow mirror allowed":              "IPAddressDeny=0.0.0.0/0 ::/0\nIPAddressAllow=127.0.0.0/8 10.20.0.20/32\nNeedDaemonReload=no\n",
	} {
		if err := CheckEgressFilter([]byte(show)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Each way the filter can fail to filter is refused with ErrEgressFilter.
func TestCheckEgressFilterFailsClosed(t *testing.T) {
	for name, show := range map[string]string{
		"empty output":              "",
		"no deny property":          "IPAddressAllow=127.0.0.0/8\nNeedDaemonReload=no\n",
		"deny unset":                "IPAddressDeny=\nIPAddressAllow=127.0.0.0/8\nNeedDaemonReload=no\n",
		"deny covers IPv4 only":     "IPAddressDeny=0.0.0.0/0\nIPAddressAllow=127.0.0.0/8\nNeedDaemonReload=no\n",
		"deny covers IPv6 only":     "IPAddressDeny=::/0\nIPAddressAllow=127.0.0.0/8\nNeedDaemonReload=no\n",
		"deny a single network":     "IPAddressDeny=10.0.0.0/8\nNeedDaemonReload=no\n",
		"allow everything IPv4":     "IPAddressDeny=0.0.0.0/0 ::/0\nIPAddressAllow=0.0.0.0/0\nNeedDaemonReload=no\n",
		"allow everything IPv6":     "IPAddressDeny=0.0.0.0/0 ::/0\nIPAddressAllow=127.0.0.0/8 ::/0\nNeedDaemonReload=no\n",
		"allow spelled any":         "IPAddressDeny=any\nIPAddressAllow=any\nNeedDaemonReload=no\n",
		"allow a /1":                "IPAddressDeny=0.0.0.0/0 ::/0\nIPAddressAllow=0.0.0.0/1\nNeedDaemonReload=no\n",
		"allow not an address":      "IPAddressDeny=0.0.0.0/0 ::/0\nIPAddressAllow=somewhere\nNeedDaemonReload=no\n",
		"drop-in not loaded":        "IPAddressDeny=0.0.0.0/0 ::/0\nIPAddressAllow=127.0.0.0/8\nNeedDaemonReload=yes\n",
		"reload state unreadable":   "IPAddressDeny=0.0.0.0/0 ::/0\nIPAddressAllow=127.0.0.0/8\nNeedDaemonReload=maybe\n",
		"line without a value sign": "IPAddressDeny 0.0.0.0/0 ::/0\n",
	} {
		err := CheckEgressFilter([]byte(show))
		if !errors.Is(err, ErrEgressFilter) {
			t.Errorf("%s: err = %v, want ErrEgressFilter", name, err)
		}
	}
}

func TestCheckUnitEgressAsksSystemdAboutTheUnit(t *testing.T) {
	var gotUnit string
	var gotProps []string
	show := func(_ context.Context, unit string, props ...string) ([]byte, error) {
		gotUnit, gotProps = unit, props
		return []byte(goodShow), nil
	}
	if err := CheckUnitEgress(context.Background(), show, "docker.service"); err != nil {
		t.Fatalf("CheckUnitEgress: %v", err)
	}
	if gotUnit != "docker.service" {
		t.Errorf("unit = %q", gotUnit)
	}
	for _, want := range []string{"IPAddressDeny", "IPAddressAllow", "NeedDaemonReload"} {
		found := false
		for _, p := range gotProps {
			found = found || p == want
		}
		if !found {
			t.Errorf("property %s not requested (asked %v)", want, gotProps)
		}
	}
}

func TestCheckUnitEgressFailsWhenSystemdCannotBeAsked(t *testing.T) {
	show := func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("no systemd") }
	err := CheckUnitEgress(context.Background(), show, "docker.service")
	if !errors.Is(err, ErrEgressFilter) || !strings.Contains(err.Error(), "no systemd") {
		t.Fatalf("err = %v, want ErrEgressFilter wrapping the cause", err)
	}
}
