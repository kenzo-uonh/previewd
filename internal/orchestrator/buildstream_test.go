package orchestrator

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Streams recorded from Docker 29.8.2 (API 1.56): the classic builder (no
// version parameter, as DockerEngine.Build sends today) and BuildKit
// (version=2). Every failure below was answered with HTTP 200.
func TestReadBuildStreamRecordedOutput(t *testing.T) {
	for file, want := range map[string]string{
		"classic-ok.jsonl":           "sha256:418d7d1f6a6dd935ed837171df7c65752432097073deb00a1357bb21acc81970",
		"buildkit-ok.jsonl":          "sha256:2baad60d3b22a90b3c92bfa9ad446e439c3898aedffa2b5d1631cf0ddc24a443",
		"classic-run-fails.jsonl":    "",
		"buildkit-run-fails.jsonl":   "",
		"buildkit-parse-error.jsonl": "",
	} {
		t.Run(file, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", "buildstream", file))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			id, err := readBuildStream(f)
			if want != "" {
				if err != nil || id != want {
					t.Fatalf("readBuildStream = %q, %v; want %s", id, err, want)
				}
				return
			}
			if !errors.Is(err, ErrBuildFailed) || id != "" {
				t.Fatalf("failed build read as %q, %v; want ErrBuildFailed", id, err)
			}
		})
	}
}

const okID = `{"aux":{"ID":"sha256:418d7d1f6a6dd935ed837171df7c65752432097073deb00a1357bb21acc81970"}}`

// Fail closed: only an error-free stream that reports the image ID is a
// successful build.
func TestReadBuildStreamFailsClosed(t *testing.T) {
	for name, stream := range map[string]string{
		"empty":                    "",
		"progress only, no ID":     `{"stream":"Step 1/2 : FROM busybox"}` + "\r\n",
		"buildkit trace only":      `{"id":"moby.buildkit.trace","aux":"Cm8KR3No"}` + "\r\n",
		"error field only":         okID + "\r\n" + `{"error":"boom"}` + "\r\n",
		"errorDetail only":         `{"errorDetail":{"message":"boom"}}` + "\r\n" + okID,
		"empty errorDetail":        `{"errorDetail":{}}` + "\r\n" + okID,
		"error after the image ID": okID + "\r\n" + `{"error":"export failed","errorDetail":{"message":"export failed"}}`,
		"malformed line":           okID + "\r\n" + `{"stream":` + "\r\n",
		"cut mid-message":          `{"stream":"Step 1/2"}` + "\r\n" + `{"aux":{"ID":"sha256:418d7d1f6a6d`,
		"ID not a digest":          `{"aux":{"ID":"busybox:latest"}}`,
		"ID short digest":          `{"aux":{"ID":"sha256:418d"}}`,
		"ID upper case":            strings.ToUpper(okID),
		"ID under another id":      `{"id":"moby.buildkit.trace","aux":{"ID":"sha256:418d7d1f6a6dd935ed837171df7c65752432097073deb00a1357bb21acc81970"}}`,
		"line one byte over":       `{"stream":"` + strings.Repeat("x", maxBuildMessageBytes-len(`{"stream":""}`)) + `"}` + "\n" + okID,
		"not JSON at all":          "HTTP/1.1 502 Bad Gateway\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			if id, err := readBuildStream(strings.NewReader(stream)); !errors.Is(err, ErrBuildFailed) {
				t.Fatalf("readBuildStream = %q, %v; want ErrBuildFailed", id, err)
			}
		})
	}
}

func TestReadBuildStreamAcceptsBothBuilders(t *testing.T) {
	for name, stream := range map[string]string{
		"classic":              okID,
		"buildkit":             `{"id":"moby.image.id","aux":{"ID":"sha256:418d7d1f6a6dd935ed837171df7c65752432097073deb00a1357bb21acc81970"}}`,
		"crlf and blank lines": "\r\n" + `{"stream":"ok"}` + "\r\n\r\n" + okID + "\r\n",
		"no trailing newline":  `{"stream":"ok"}` + "\n" + okID,
		// The bound counts the newline: the longest line is one byte short.
		"line at the bound": `{"stream":"` + strings.Repeat("x", maxBuildMessageBytes-1-len(`{"stream":""}`)) + `"}` + "\n" + okID,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readBuildStream(strings.NewReader(stream)); err != nil {
				t.Fatalf("readBuildStream: %v", err)
			}
		})
	}
}

// The daemon's error text repeats the PR's Dockerfile: it is bounded and
// quoted, never passed through raw.
func TestReadBuildStreamBoundsUntrustedErrorText(t *testing.T) {
	hostile := strings.Repeat("A", 4096) + "\n\x1b[31mfake log line"
	stream := `{"error":"x","errorDetail":{"message":` + jsonString(hostile) + `}}`
	_, err := readBuildStream(strings.NewReader(stream))
	if !errors.Is(err, ErrBuildFailed) {
		t.Fatalf("err = %v", err)
	}
	msg := err.Error()
	if len(msg) > maxBuildErrorBytes+64 || strings.ContainsAny(msg, "\n\x1b") {
		t.Fatalf("error text not bounded or not quoted (%d bytes): %q", len(msg), msg[:min(len(msg), 120)])
	}
}

func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte("0123456789abcdef"[r>>4])
			b.WriteByte("0123456789abcdef"[r&0xf])
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
