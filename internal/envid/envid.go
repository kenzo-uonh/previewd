// Package envid derives environment identifiers. An ID names the container,
// its network, its image tag, its staged-secrets directory and its Traefik
// route, so it must be a valid DNS label and unique per repository, branch
// and pull request.
package envid

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const (
	// MaxLen is the RFC 1123 label limit.
	MaxLen = 63

	prefix  = "pr-"
	hashLen = 10 // hex digits: 40 bits of SHA-256(repo, branch)
)

// ErrInvalid reports an identifier that Generate cannot have produced.
var ErrInvalid = errors.New("invalid environment id")

// Generate returns "pr-<prID>-<hash>", where hash covers the repository and
// the head branch. The same pull request number in two repositories, or on
// two branches, yields two IDs. Repository names compare ASCII
// case-insensitively, as on GitHub (owner and repository names are ASCII);
// branch names are case-sensitive, as in git. Every input byte is hashed
// as-is, so distinct invalid UTF-8 inputs never fold together. The longest
// result (20-digit prID) is 34 bytes.
func Generate(repo, branch string, prID uint64) string {
	h := sha256.New()
	repo = asciiLower(repo)
	// Length-prefix repo so ("a/b", "c") and ("a/bc", "") cannot collide.
	h.Write(binary.AppendUvarint(nil, uint64(len(repo))))
	h.Write([]byte(repo))
	h.Write([]byte(branch))
	sum := hex.EncodeToString(h.Sum(nil))

	return prefix + strconv.FormatUint(prID, 10) + "-" + sum[:hashLen]
}

// ParsePR recovers the pull request number from an ID produced by Generate.
// It accepts only the canonical form: no sign, no leading zero, lowercase
// hex hash of the exact length.
func ParsePR(id string) (uint64, error) {
	rest, ok := strings.CutPrefix(id, prefix)
	if !ok {
		return 0, ErrInvalid
	}
	num, hash, ok := strings.Cut(rest, "-")
	if !ok || len(hash) != hashLen || !isLowerHex(hash) {
		return 0, ErrInvalid
	}
	if num == "" || (len(num) > 1 && num[0] == '0') || !isDigits(num) {
		return 0, ErrInvalid
	}
	n, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, ErrInvalid
	}
	return n, nil
}

// Valid reports whether id is a canonical environment ID.
func Valid(id string) bool {
	_, err := ParsePR(id)
	return err == nil
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func isDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isLowerHex(s string) bool {
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
