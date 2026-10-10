package validate

import (
	"errors"
	"strings"
	"testing"
)

const busyboxDigest = "sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"

// BaseImage normalizes every spelling the daemon resolves to the same
// name:tag@digest into one canonical form.
func TestBaseImageCanonical(t *testing.T) {
	want := "docker.io/library/busybox:1.37@" + busyboxDigest
	for _, s := range []string{
		"busybox:1.37@" + busyboxDigest,
		"library/busybox:1.37@" + busyboxDigest,
		"docker.io/library/busybox:1.37@" + busyboxDigest,
		"index.docker.io/library/busybox:1.37@" + busyboxDigest,
	} {
		if got, err := BaseImage(s); err != nil || got != want {
			t.Errorf("BaseImage(%q) = %q, %v; want %q", s, got, err, want)
		}
	}
	if got, err := BaseImage("registry.corp:5000/team/app:v2@" + busyboxDigest); err != nil || got != "registry.corp:5000/team/app:v2@"+busyboxDigest {
		t.Errorf("private registry = %q, %v", got, err)
	}
	nameTag, dgst, err := SplitBaseImage(want)
	if err != nil || nameTag != "docker.io/library/busybox:1.37" || dgst != busyboxDigest {
		t.Errorf("SplitBaseImage = %q, %q, %v", nameTag, dgst, err)
	}
}

// Fail closed: a reference without both its tag and its sha256 digest is
// refused. A digest-only reference cannot build offline on the supported
// engine (task E0); a tag-only one is not pinned.
func TestBaseImageRefuses(t *testing.T) {
	for _, s := range []string{
		"", "busybox", "busybox:latest", "scratch", "busybox@" + busyboxDigest,
		"Busybox:latest@" + busyboxDigest,
		"busybox:latest@sha256:" + strings.Repeat("0", 63),
		"busybox:latest@sha256:" + strings.Repeat("G", 64),
		"busybox:latest@sha512:" + strings.Repeat("0", 128),
		"busybox:latest@" + busyboxDigest + "x",
		"busybox :latest@" + busyboxDigest,
		strings.Repeat("a", maxImageRefLen) + ":latest@" + busyboxDigest,
	} {
		if got, err := BaseImage(s); err == nil {
			t.Errorf("BaseImage(%q) = %q accepted", s, got)
		}
	}
	for _, s := range []string{"busybox:latest", "busybox@" + busyboxDigest} {
		if _, err := BaseImage(s); !errors.Is(err, ErrImageNotPinned) {
			t.Errorf("%s: %v, want ErrImageNotPinned", s, err)
		}
	}
	if _, _, err := SplitBaseImage("busybox@" + busyboxDigest); err == nil {
		t.Error("SplitBaseImage accepted a digest-only reference")
	}
}

func TestAllowedBaseImages(t *testing.T) {
	got, err := AllowedBaseImages("busybox:latest@" + busyboxDigest + ",registry.corp/app:v1@" + busyboxDigest)
	if err != nil || len(got) != 2 || !got["docker.io/library/busybox:latest@"+busyboxDigest] || !got["registry.corp/app:v1@"+busyboxDigest] {
		t.Fatalf("AllowedBaseImages = %v, %v", got, err)
	}
	for _, bad := range []string{
		"",
		",",
		"busybox:latest@" + busyboxDigest + ",",
		"busybox:latest",
		"busybox@" + busyboxDigest,
		"busybox:latest@" + busyboxDigest + ",docker.io/library/busybox:latest@" + busyboxDigest, // twice, spelled differently
		" busybox:latest@" + busyboxDigest,
	} {
		if got, err := AllowedBaseImages(bad); err == nil {
			t.Errorf("AllowedBaseImages(%q) = %v accepted", bad, got)
		}
	}
}
