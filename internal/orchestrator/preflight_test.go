package orchestrator

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// pinned is testBase as a PR writes it.
const pinned = "busybox:latest@" + testBaseDigest

// Accepted: only context paths, allowlisted bases (in every spelling the
// daemon resolves to the same reference), earlier stages and scratch.
func TestPreflightAccepts(t *testing.T) {
	for name, df := range map[string]string{
		"pinned":                "FROM " + pinned + "\nRUN echo ok\n",
		"fully qualified":       "FROM docker.io/library/" + pinned + "\n",
		"lower-case from as":    "from " + pinned + " as build\nrun true\n",
		"scratch":               "FROM scratch\nCOPY app /app\n",
		"global ARG":            "ARG BASE=" + pinned + "\nFROM ${BASE}\n",
		"chained ARG":           "ARG NAME=busybox\nARG BASE=${NAME}:latest@" + testBaseDigest + "\nFROM $BASE\n",
		"ARG default form":      "ARG BASE=" + pinned + "\nFROM ${BASE:-alpine}\n",
		"ARG redeclared":        "ARG BASE=alpine\nARG BASE=" + pinned + "\nFROM $BASE\n",
		"builtin overridden":    "ARG TARGETARCH=" + pinned + "\nFROM ${TARGETARCH}\n",
		"earlier stage":         "FROM " + pinned + " AS build\nRUN make\nFROM build AS test\nFROM build\nCOPY --from=test /a /a\n",
		"stage by index":        "FROM " + pinned + "\nRUN make\nFROM scratch\nCOPY --from=0 /a /a\n",
		"stage name any case":   "FROM " + pinned + " AS Build\nFROM scratch\nCOPY --from=BUILD /a /a\n",
		"stage defined later":   "FROM " + pinned + "\nCOPY --from=late /a /a\nFROM " + pinned + " AS late\n",
		"ADD local":             "FROM " + pinned + "\nADD --chown=1:1 --chmod=0644 --link app.tar.gz /srv/\nADD a b /dst/\n",
		"COPY flags":            "FROM " + pinned + "\nCOPY --chown=1:1 --chmod=0755 --link --parents --exclude=*.md ./ /app/\n",
		"ADD exclude":           "FROM " + pinned + "\nADD --exclude=*.tmp src /src\n",
		"RUN heredoc":           "FROM " + pinned + "\nRUN <<EOF\necho a\necho b\nEOF\n",
		"COPY heredoc":          "FROM " + pinned + "\nCOPY <<EOF /etc/conf\nkey=value\nEOF\n",
		"every allowed command": "FROM " + pinned + "\nARG V=1\nENV A=b\nLABEL k=v\nMAINTAINER x\nWORKDIR /w\nUSER 1000\nEXPOSE 8080\nVOLUME /data\nSHELL [\"/bin/sh\", \"-c\"]\nSTOPSIGNAL SIGTERM\nHEALTHCHECK CMD true\nENTRYPOINT [\"/bin/sh\"]\nCMD [\"-c\", \"true\"]\n",
		"escape directive":      "# escape=`\nFROM " + pinned + "\nRUN echo a `\n  b\n",
		"check directive":       "# check=skip=all\nFROM " + pinned + "\n",
		"stage-scoped ARG":      "FROM " + pinned + "\nARG URL=https://example.invalid\nRUN echo $URL\n",
		"comment says syntax":   "FROM " + pinned + "\n# syntax=docker/dockerfile:1\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := Preflight([]byte(df), testBases); err != nil {
				t.Fatalf("Preflight refused:\n%s\nerror: %v", df, err)
			}
		})
	}
}

// Every refusal is ErrPreflight. Each row is one control.
func TestPreflightRefuses(t *testing.T) {
	other := "busybox:latest@sha256:" + strings.Repeat("0", 64)
	for name, df := range map[string]string{
		// Frontend selection: the daemon would pull the frontend image.
		"syntax":              "# syntax=docker/dockerfile:1\nFROM " + pinned + "\n",
		"syntax no space":     "#syntax=docker/dockerfile:1\nFROM " + pinned + "\n",
		"syntax upper case":   "# SYNTAX=docker/dockerfile:1\nFROM " + pinned + "\n",
		"syntax after BOM":    "\uFEFF# syntax=docker/dockerfile:1\nFROM " + pinned + "\n",
		"syntax after escape": "# escape=\\\n# syntax=evil/frontend\nFROM " + pinned + "\n",
		"syntax shebang":      "#!/usr/bin/env buildctl\n# syntax=evil/frontend\nFROM " + pinned + "\n",
		"syntax slashes":      "//syntax=evil/frontend\nFROM " + pinned + "\n",
		"syntax json":         `{"syntax": "evil/frontend"}`,

		// Base images.
		"FROM by tag":              "FROM busybox:latest\n",
		"FROM bare name":           "FROM busybox\n",
		"FROM other digest":        "FROM " + other + "\n",
		"FROM other registry":      "FROM registry.example.invalid/" + pinned + "\n",
		"FROM other name":          "FROM alpine:latest@" + testBaseDigest + "\n",
		"FROM other tag":           "FROM busybox:1.37@" + testBaseDigest + "\n",
		"FROM digest only":         "FROM busybox@" + testBaseDigest + "\n",
		"FROM platform":            "FROM --platform=linux/amd64 " + pinned + "\n",
		"FROM platform variable":   "FROM --platform=$BUILDPLATFORM " + pinned + "\n",
		"FROM SCRATCH":             "FROM SCRATCH\n",
		"FROM later stage":         "FROM later\nFROM " + pinned + " AS later\n",
		"FROM itself":              "FROM self AS self\n",
		"FROM stage other case":    "FROM " + pinned + " AS build\nFROM Build\n",
		"second FROM not allowed":  "FROM " + pinned + "\nFROM alpine:3\n",
		"FROM builtin":             "FROM ${TARGETARCH}\n",
		"FROM builtin default":     "FROM ${TARGETARCH:-" + pinned + "}\n",
		"FROM builtin alternative": "ARG B=" + pinned + "\nFROM ${B}${TARGETVARIANT:+-evil}\n",
		"FROM builtin declared":    "ARG TARGETARCH\nFROM ${TARGETARCH:-" + pinned + "}\n",
		"FROM ARG without default": "ARG BASE\nFROM ${BASE:-" + pinned + "}\n",
		"FROM tainted ARG":         "ARG ARCH=$TARGETARCH\nARG BASE=" + pinned + "\nFROM ${BASE}${ARCH:+x}\n",
		"FROM tainted by chain":    "ARG A=${BUILDOS}\nARG B=${A}\nFROM ${B:-" + pinned + "}\n",
		"FROM stage-scoped ARG":    "FROM " + pinned + " AS a\nARG BASE=" + pinned + "\nFROM ${BASE}\n",
		"FROM undefined variable":  "FROM ${NOPE:-" + pinned + "}\n",
		"FROM empty":               "ARG E=\nFROM ${E}\n",
		"FROM bad expansion":       "ARG B=" + pinned + "\nFROM ${B:?}x\n",

		// ADD from the network.
		"ADD https":            "FROM " + pinned + "\nADD https://example.invalid/x.tgz /x\n",
		"ADD http":             "FROM " + pinned + "\nADD http://example.invalid/x /x\n",
		"ADD git https":        "FROM " + pinned + "\nADD https://example.invalid/r.git#main /src\n",
		"ADD git scheme":       "FROM " + pinned + "\nADD git://example.invalid/r.git /src\n",
		"ADD git ssh":          "FROM " + pinned + "\nADD ssh://git@example.invalid/r.git /src\n",
		"ADD scp style":        "FROM " + pinned + "\nADD git@example.invalid:org/r.git /src\n",
		"ADD github prefix":    "FROM " + pinned + "\nADD github.com/org/repo /src\n",
		"ADD upper scheme":     "FROM " + pinned + "\nADD HTTPS://example.invalid/x /x\n",
		"ADD second source":    "FROM " + pinned + "\nADD app https://example.invalid/x /dst/\n",
		"ADD JSON form":        "FROM " + pinned + "\nADD [\"https://example.invalid/x\", \"/x\"]\n",
		"ADD variable":         "FROM " + pinned + "\nARG U=https://example.invalid/x\nADD $U /x\n",
		"ADD braced variable":  "FROM " + pinned + "\nADD ${U} /x\n",
		"ADD checksum":         "FROM " + pinned + "\nADD --checksum=sha256:" + strings.Repeat("a", 64) + " app /x\n",
		"ADD keep-git-dir":     "FROM " + pinned + "\nADD --keep-git-dir=true app /x\n",
		"ADD unpack":           "FROM " + pinned + "\nADD --unpack=true app.tgz /x\n",
		"ADD unknown flag":     "FROM " + pinned + "\nADD --nope app /x\n",
		"ADD escaped variable": "# escape=`\nFROM " + pinned + "\nADD `$U /x\n",

		// RUN flags.
		"RUN network none":     "FROM " + pinned + "\nRUN --network=none true\n",
		"RUN network host":     "FROM " + pinned + "\nRUN --network=host curl x\n",
		"RUN network default":  "FROM " + pinned + "\nRUN --network=default curl x\n",
		"RUN mount cache":      "FROM " + pinned + "\nRUN --mount=type=cache,target=/root/.cache true\n",
		"RUN mount secret":     "FROM " + pinned + "\nRUN --mount=type=secret,id=x cat /run/secrets/x\n",
		"RUN mount ssh":        "FROM " + pinned + "\nRUN --mount=type=ssh true\n",
		"RUN mount image":      "FROM " + pinned + "\nRUN --mount=type=bind,from=alpine,target=/a true\n",
		"RUN mount tmpfs":      "FROM " + pinned + "\nRUN --mount=type=tmpfs,target=/t true\n",
		"RUN security":         "FROM " + pinned + "\nRUN --security=insecure true\n",
		"RUN security sandbox": "FROM " + pinned + "\nRUN --security=sandbox true\n",
		"RUN device":           "FROM " + pinned + "\nRUN --device=/dev/kvm true\n",
		"RUN unknown flag":     "FROM " + pinned + "\nRUN --nope true\n",
		"RUN flag upper case":  "FROM " + pinned + "\nrun --NETWORK=host true\n",

		// COPY --from an image.
		"COPY from image":         "FROM " + pinned + "\nCOPY --from=alpine:3 /etc/passwd /x\n",
		"COPY from allowed image": "FROM " + pinned + "\nCOPY --from=" + pinned + " /bin/sh /x\n",
		"COPY from index too big": "FROM " + pinned + "\nCOPY --from=1 /a /a\n",
		"COPY from negative":      "FROM " + pinned + "\nCOPY --from=-1 /a /a\n",
		"COPY from variable":      "FROM " + pinned + " AS a\nARG S=a\nCOPY --from=$S /a /a\n",
		"COPY from unnamed":       "FROM " + pinned + "\nFROM scratch\nCOPY --from=stage-0 /a /a\n",

		// ONBUILD and the unknown.
		"ONBUILD":             "FROM " + pinned + "\nONBUILD RUN true\n",
		"ONBUILD ADD":         "FROM " + pinned + "\nONBUILD ADD https://example.invalid/x /x\n",
		"unknown instruction": "FROM " + pinned + "\nFETCH https://example.invalid\n",
		"empty":               "",
		"comments only":       "# nothing\n",
		"ARG only":            "ARG A=1\n",
		"instruction first":   "RUN true\nFROM " + pinned + "\n",
		"FROM without base":   "FROM\n",
		"FROM four words":     "FROM " + pinned + " AS a b\n",
		"bad stage name":      "FROM " + pinned + " AS 0bad\n",
		"oversized":           "FROM " + pinned + "\n#" + strings.Repeat("x", maxDockerfileBytes) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			err := Preflight([]byte(df), testBases)
			if !errors.Is(err, ErrPreflight) {
				t.Fatalf("Preflight accepted or failed open:\n%s\nerror: %v", df, err)
			}
		})
	}
}

// An empty allowlist accepts no image: only scratch and stages build.
func TestPreflightEmptyAllowlist(t *testing.T) {
	for _, bases := range []map[string]bool{nil, {}} {
		if err := Preflight([]byte("FROM "+pinned+"\n"), bases); !errors.Is(err, ErrPreflight) {
			t.Fatalf("empty allowlist accepted an image: %v", err)
		}
	}
}

// PR-controlled text is bounded in a refusal.
func TestPreflightRefusalIsBounded(t *testing.T) {
	long := strings.Repeat("a", 100_000)
	for _, df := range []string{
		"FROM " + long + "\n",
		"FROM " + pinned + "\nADD https://" + long + " /x\n",
		"FROM " + pinned + "\nCOPY --from=" + long + " /x /x\n",
		"FROM " + pinned + "\n" + long + " x\n",
	} {
		err := Preflight([]byte(df), testBases)
		if !errors.Is(err, ErrPreflight) {
			t.Fatalf("accepted: %v", err)
		}
		if len(err.Error()) > 1024 {
			t.Fatalf("refusal of %d bytes quotes the Dockerfile unbounded", len(err.Error()))
		}
	}
}

// allowedCommands is the oracle of the fuzz target, read from the AST and
// independent of Preflight's typed checks.
var allowedCommands = map[string]bool{
	"from": true, "arg": true, "env": true, "label": true, "maintainer": true, "workdir": true,
	"user": true, "expose": true, "volume": true, "cmd": true, "entrypoint": true,
	"healthcheck": true, "shell": true, "stopsignal": true, "run": true, "add": true, "copy": true,
}

// FuzzPreflight: no panic, and an accepted Dockerfile holds only allowed
// instructions, no syntax directive, no RUN flag, no FROM --platform, no
// ADD source with a scheme, and only allowlisted bases.
func FuzzPreflight(f *testing.F) {
	for _, s := range []string{
		"FROM " + pinned + "\nRUN true\n",
		"ARG B=" + pinned + "\nFROM $B AS b\nFROM b\nCOPY --from=b / /\n",
		"FROM " + pinned + "\nADD https://example.invalid/x /x\n",
		"FROM scratch\nADD app ://\n",
		"# syntax=x\nFROM " + pinned + "\n",
		"FROM " + pinned + "\nRUN --network=host true\n",
		"FROM ${TARGETARCH:-" + pinned + "}\n",
		"FROM scratch\nONBUILD RUN x\n",
		"# escape=`\nFROM " + pinned + "\nRUN <<EOF\nx\nEOF\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, df []byte) {
		if Preflight(df, testBases) != nil {
			return
		}
		if _, _, _, ok := parser.DetectSyntax(df); ok {
			t.Fatalf("accepted a syntax directive:\n%q", df)
		}
		res, err := parser.Parse(bytes.NewReader(df))
		if err != nil {
			t.Fatalf("accepted a Dockerfile the parser refuses: %v", err)
		}
		froms := 0
		for _, n := range res.AST.Children {
			cmd := strings.ToLower(n.Value)
			if !allowedCommands[cmd] {
				t.Fatalf("accepted instruction %q:\n%q", n.Value, df)
			}
			switch cmd {
			case "run":
				if len(n.Flags) > 0 {
					t.Fatalf("accepted RUN flags %q", n.Flags)
				}
			case "from":
				froms++
				for _, fl := range n.Flags {
					if strings.Contains(strings.ToLower(fl), "platform") {
						t.Fatalf("accepted FROM %q", n.Flags)
					}
				}
			case "add":
				// The last argument is the destination, a path in the image:
				// only the sources are fetched.
				var args []string
				for a := n.Next; a != nil; a = a.Next {
					args = append(args, a.Value)
				}
				for _, src := range args[:max(len(args)-1, 0)] {
					if strings.Contains(src, "://") {
						t.Fatalf("accepted ADD %q", src)
					}
				}
			}
		}
		if froms == 0 {
			t.Fatalf("accepted a Dockerfile without FROM:\n%q", df)
		}
	})
}

// --- build context ---

type entry struct {
	name, link string
	mode       os.FileMode
	body       string
}

// layout writes entries under a new directory: a name ending in / is a
// directory, a link a symlink.
func layout(t *testing.T, entries ...entry) string {
	t.Helper()
	dir := t.TempDir()
	for _, e := range entries {
		p := filepath.Join(dir, e.name)
		var err error
		switch {
		case strings.HasSuffix(e.name, "/"):
			err = os.MkdirAll(p, 0o755)
		case e.link != "":
			if err = os.MkdirAll(filepath.Dir(p), 0o755); err == nil {
				err = os.Symlink(e.link, p)
			}
		default:
			if err = os.MkdirAll(filepath.Dir(p), 0o755); err == nil {
				err = os.WriteFile(p, []byte(e.body), cmpMode(e.mode))
			}
			if err == nil && e.mode != 0 {
				err = os.Chmod(p, e.mode)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func cmpMode(m os.FileMode) os.FileMode {
	if m == 0 {
		return 0o644
	}
	return m.Perm()
}

var okDockerfile = entry{name: "Dockerfile", body: "FROM " + pinned + "\nCOPY . /app\n"}

func prepare(t *testing.T, src string, maxBytes int64) (*os.File, error) {
	t.Helper()
	f, err := PrepareBuildContext(src, filepath.Join(t.TempDir(), "context.tar"), maxBytes, testBases)
	if f != nil {
		t.Cleanup(func() { _ = f.Close() })
	}
	return f, err
}

func readTar(t *testing.T, r io.Reader) map[string]*tar.Header {
	t.Helper()
	out := map[string]*tar.Header{}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = hdr
	}
}

// The context keeps files, directories and symlinks that resolve inside it
// (node_modules/.bin style), with permission bits only and root ownership.
func TestPrepareBuildContextPacks(t *testing.T) {
	src := layout(t,
		okDockerfile,
		entry{name: "app/main.go", body: "package main"},
		entry{name: "bin/run", body: "#!/bin/sh", mode: 0o4755 | os.ModeSetuid},
		entry{name: "node_modules/typescript/bin/tsc", body: "tsc"},
		entry{name: "node_modules/.bin/tsc", link: "../typescript/bin/tsc"},
		entry{name: "current", link: "app"},
		entry{name: "empty/"},
	)
	f, err := prepare(t, src, 1<<20)
	if err != nil {
		t.Fatalf("PrepareBuildContext: %v", err)
	}
	hdrs := readTar(t, f)
	want := []string{"Dockerfile", "app/", "app/main.go", "bin/", "bin/run", "current", "empty/",
		"node_modules/", "node_modules/.bin/", "node_modules/.bin/tsc", "node_modules/typescript/",
		"node_modules/typescript/bin/", "node_modules/typescript/bin/tsc"}
	if got := slices.Sorted(maps.Keys(hdrs)); !slices.Equal(got, want) {
		t.Fatalf("entries = %q, want %q", got, want)
	}
	if h := hdrs["node_modules/.bin/tsc"]; h.Typeflag != tar.TypeSymlink || h.Linkname != "../typescript/bin/tsc" {
		t.Fatalf("symlink packed as %+v", h)
	}
	if h := hdrs["bin/run"]; h.Mode != 0o755 {
		t.Fatalf("bin/run mode %o: setuid must be dropped", h.Mode)
	}
	for name, h := range hdrs {
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" {
			t.Fatalf("%s owned by %d:%d (%s:%s), want root", name, h.Uid, h.Gid, h.Uname, h.Gname)
		}
	}
}

// Fail closed: every row is refused before any request could be sent.
func TestPrepareBuildContextRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		entries []entry
		want    error
	}{
		"no Dockerfile":             {[]entry{{name: "app/main.go", body: "x"}}, ErrPreflight},
		"lower-case dockerfile":     {[]entry{{name: "dockerfile", body: okDockerfile.body}}, ErrPreflight},
		"Dockerfile is a dir":       {[]entry{{name: "Dockerfile/"}}, ErrPreflight},
		"Dockerfile symlink":        {[]entry{{name: "real", body: okDockerfile.body}, {name: "Dockerfile", link: "real"}}, ErrPreflight},
		"Dockerfile refused":        {[]entry{{name: "Dockerfile", body: "FROM busybox:latest\n"}}, ErrPreflight},
		"Dockerfile too large":      {[]entry{{name: "Dockerfile", body: "FROM " + pinned + "\n#" + strings.Repeat("x", maxDockerfileBytes)}}, ErrPreflight},
		"absolute symlink":          {[]entry{okDockerfile, {name: "passwd", link: "/etc/passwd"}}, ErrPreflight},
		"parent symlink":            {[]entry{okDockerfile, {name: "up", link: ".."}}, ErrPreflight},
		"escape below":              {[]entry{okDockerfile, {name: "a/b/c", link: "../../../x"}}, ErrPreflight},
		"escape through a link":     {[]entry{okDockerfile, {name: "here", link: "."}, {name: "sub/x", link: "../here/.."}}, ErrPreflight},
		"escape through a chain":    {[]entry{okDockerfile, {name: "a", link: "b"}, {name: "b", link: "../outside"}}, ErrPreflight},
		"dangling symlink":          {[]entry{okDockerfile, {name: "gone", link: "missing"}}, ErrPreflight},
		"symlink loop":              {[]entry{okDockerfile, {name: "l1", link: "l2"}, {name: "l2", link: "l1"}}, ErrPreflight},
		"nested Dockerfile ignored": {[]entry{{name: "sub/Dockerfile", body: okDockerfile.body}}, ErrPreflight},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := prepare(t, layout(t, tc.entries...), 4<<20)
			if !errors.Is(err, tc.want) {
				t.Fatalf("PrepareBuildContext = %v, want %v", err, tc.want)
			}
		})
	}
}

// The cap is on the tar streamed: the exact size passes, one byte less is
// refused, and so is one oversized file before it is read.
func TestPrepareBuildContextCap(t *testing.T) {
	src := layout(t, okDockerfile, entry{name: "blob", body: strings.Repeat("x", 10_000)})
	f, err := prepare(t, src, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepare(t, src, st.Size()); err != nil {
		t.Fatalf("context of exactly the cap refused: %v", err)
	}
	if _, err := prepare(t, src, st.Size()-1); !errors.Is(err, ErrContextTooLarge) {
		t.Fatalf("context one byte above the cap: %v, want ErrContextTooLarge", err)
	}
	if _, err := prepare(t, src, 5_000); !errors.Is(err, ErrContextTooLarge) {
		t.Fatalf("oversized file: %v, want ErrContextTooLarge", err)
	}
	if _, err := prepare(t, src, 0); err == nil {
		t.Fatal("a zero cap accepted")
	}
}

// The returned tar is rewound, and an existing tar path is never reused.
func TestPrepareBuildContextFile(t *testing.T) {
	src := layout(t, okDockerfile)
	tarPath := filepath.Join(t.TempDir(), "context.tar")
	f, err := PrepareBuildContext(src, tarPath, 1<<20, testBases)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	got, err := tarFile(f, dockerfileName)
	if err != nil || got != okDockerfile.body {
		t.Fatalf("Dockerfile in the tar = %q, %v", got, err)
	}
	st, err := os.Stat(tarPath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("tar mode %v, %v: want 0600", st.Mode(), err)
	}
	if _, err := PrepareBuildContext(src, tarPath, 1<<20, testBases); err == nil {
		t.Fatal("an existing tar path was reused")
	}
}
