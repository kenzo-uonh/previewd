package validate

import (
	"errors"
	"fmt"
	"strings"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
)

// maxImageRefLen bounds an image reference before it is parsed (the
// reference grammar allows 255 bytes of name, plus tag and digest).
const maxImageRefLen = 512

// ErrImageNotPinned is an image reference without both a tag and a sha256
// digest.
var ErrImageNotPinned = errors.New("image reference is not pinned as name:tag@sha256:<digest>")

// BaseImage normalizes an image reference the way the daemon's Dockerfile
// frontend does (distribution/reference, docker.io/library defaults) and
// returns its canonical name:tag@sha256:<hex> form. Both parts are required
// (ErrImageNotPinned otherwise), as measured on the supported engine (task
// E0, BuildKit on the containerd image store): the daemon contacts the
// registry first whatever the pull flag, then falls back to the local image
// by its name:tag, and refuses it unless it is the pinned digest. A
// digest-only reference has no local fallback, so it cannot build offline;
// a tag-only one is not pinned.
func BaseImage(s string) (string, error) {
	if s == "" || len(s) > maxImageRefLen {
		return "", fmt.Errorf("invalid image reference %s", Quote(s))
	}
	ref, err := reference.ParseNormalizedNamed(s)
	if err != nil {
		return "", fmt.Errorf("invalid image reference %s: %w", Quote(s), err)
	}
	canonical, digested := ref.(reference.Canonical)
	_, tagged := ref.(reference.Tagged)
	if !digested || !tagged {
		return "", fmt.Errorf("%w: %s", ErrImageNotPinned, Quote(s))
	}
	if d := canonical.Digest(); d.Algorithm() != digest.SHA256 || d.Validate() != nil {
		return "", fmt.Errorf("%w: %s", ErrImageNotPinned, Quote(s))
	}
	return ref.String(), nil
}

// AllowedBaseImages parses PREVIEWD_ALLOWED_BASE_IMAGES: comma-separated
// name:tag@sha256:<64 hex> references (BaseImage), returned in canonical
// form. An empty list, an empty entry, an unpinned reference, or an image
// listed twice is an error.
func AllowedBaseImages(s string) (map[string]bool, error) {
	if s == "" {
		return nil, errors.New("no base image allowed: list name:tag@sha256:<digest> references")
	}
	out := map[string]bool{}
	for i, entry := range strings.Split(s, ",") {
		canonical, err := BaseImage(entry)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
		if out[canonical] {
			return nil, fmt.Errorf("entry %d: %s listed twice", i+1, Quote(entry))
		}
		out[canonical] = true
	}
	return out, nil
}

// SplitBaseImage splits a canonical BaseImage reference into its name:tag,
// the local record the daemon falls back to, and its digest.
func SplitBaseImage(canonical string) (nameTag, dgst string, err error) {
	if _, err := BaseImage(canonical); err != nil {
		return "", "", err
	}
	nameTag, dgst, _ = strings.Cut(canonical, "@")
	return nameTag, dgst, nil
}
