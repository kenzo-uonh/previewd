package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCreds is systemd-creds: it writes "ENCRYPTED(<name>)" to the output
// path, and records the secret it was given.
type fakeCreds struct {
	args     [][]string
	secrets  []string
	terminal bool
	hidden   int // hideInput calls not yet restored
	locked   bool
	lockErr  error
	noDumps  bool
	coreErr  error
	fail     error
}

func (f *fakeCreds) host() credentialsHost {
	return credentialsHost{
		noCoreDumps: func() error { f.noDumps = f.coreErr == nil; return f.coreErr },
		lockMemory: func() error {
			if !f.noDumps {
				return errors.New("memory locked before core dumps were disabled")
			}
			f.locked = f.lockErr == nil
			return f.lockErr
		},
		hideInput: func() (func() error, bool, error) {
			if f.terminal {
				f.hidden++
			}
			return func() error { f.hidden--; return nil }, f.terminal, nil
		},
		encrypt: func(_ context.Context, args []string, secret []byte) error {
			if !f.noDumps || !f.locked {
				return errors.New("core dumps not disabled and memory not locked before a secret was handled")
			}
			if f.terminal && f.hidden != 0 {
				return errors.New("the terminal echo was not restored before encrypting")
			}
			f.args = append(f.args, args)
			f.secrets = append(f.secrets, string(secret))
			if f.fail != nil {
				return f.fail
			}
			return os.WriteFile(args[len(args)-1], []byte("ENCRYPTED("+strings.TrimPrefix(args[1], "--name=")+")"), 0o644)
		},
	}
}

func runCredsCmd(t *testing.T, f *fakeCreds, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := runSetupCredentials(context.Background(), args, strings.NewReader(stdin), &out, &errOut, f.host())
	return code, out.String(), errOut.String()
}

func TestSetupCredentialsEncryptsAPipedSecret(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credstore.encrypted")
	f := &fakeCreds{}
	pem := "-----BEGIN PRIVATE KEY-----\nMIIBVQ==\n-----END PRIVATE KEY-----\n"
	code, out, errOut := runCredsCmd(t, f, pem, "-dir", dir, "-with-key", "host+tpm2", "github-app-key")
	if code != exitOK {
		t.Fatalf("exit %d, %q", code, errOut)
	}
	target := filepath.Join(dir, "github-app-key")
	if got := strings.Join(f.args[0], " "); got != "encrypt --name=github-app-key --with-key=host+tpm2 - "+filepath.Join(dir, ".github-app-key.previewd-tmp") {
		t.Errorf("systemd-creds %s", got)
	}
	if f.secrets[0] != strings.TrimRight(pem, "\n") {
		t.Errorf("secret %q", f.secrets[0])
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "ENCRYPTED(github-app-key)" {
		t.Errorf("target %q, %v", b, err)
	}
	if fi, err := os.Stat(target); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, %v", fi.Mode(), err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("credstore mode %v, %v", fi.Mode(), err)
	}
	if !strings.Contains(out, "LoadCredentialEncrypted=github-app-key:"+target) || strings.Contains(out+errOut, "MIIBVQ") {
		t.Errorf("output:\n%s%s", out, errOut)
	}
	// Nothing in the clear is left in the directory.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("directory holds %v", entries)
	}
}

func TestSetupCredentialsAsksTwiceOnATerminal(t *testing.T) {
	dir := t.TempDir()
	f := &fakeCreds{terminal: true}
	code, out, errOut := runCredsCmd(t, f, "hook-s3cret\nhook-s3cret\ntok-0123\ntok-0123\n", "-dir", dir, "webhook_secret", "trigger-token")
	if code != exitOK || len(f.secrets) != 2 || f.secrets[0] != "hook-s3cret" || f.secrets[1] != "tok-0123" || f.hidden != 0 {
		t.Fatalf("exit %d, secrets %q, hidden %d, %q", code, f.secrets, f.hidden, errOut)
	}
	if strings.Contains(out+errOut, "s3cret") || strings.Contains(out+errOut, "tok-0123") {
		t.Errorf("a secret was printed:\n%s%s", out, errOut)
	}

	f = &fakeCreds{terminal: true}
	if code, _, errOut := runCredsCmd(t, f, "one\ntwo\n", "-dir", t.TempDir(), "webhook_secret"); code != exitUsage || !strings.Contains(errOut, "differ") || len(f.secrets) != 0 || f.hidden != 0 {
		t.Errorf("mismatch: exit %d, %q, encrypted %d, hidden %d", code, errOut, len(f.secrets), f.hidden)
	}
}

func TestSetupCredentialsFailsClosed(t *testing.T) {
	existing := t.TempDir()
	if err := os.WriteFile(filepath.Join(existing, "webhook_secret"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		f     *fakeCreds
		stdin string
		args  []string
	}{
		"no name":            {&fakeCreds{}, "x", []string{"-dir", t.TempDir()}},
		"name as a path":     {&fakeCreds{}, "x", []string{"-dir", t.TempDir(), "../etc/shadow"}},
		"name twice":         {&fakeCreds{}, "x", []string{"-dir", t.TempDir(), "a", "a"}},
		"relative dir":       {&fakeCreds{}, "x", []string{"-dir", "credstore", "a"}},
		"unknown key":        {&fakeCreds{}, "x", []string{"-dir", t.TempDir(), "-with-key", "null", "a"}},
		"exists":             {&fakeCreds{}, "x", []string{"-dir", existing, "webhook_secret"}},
		"memory not locked":  {&fakeCreds{lockErr: errors.New("EPERM")}, "x", []string{"-dir", t.TempDir(), "a"}},
		"core dumps on":      {&fakeCreds{coreErr: errors.New("EPERM")}, "x", []string{"-dir", t.TempDir(), "a"}},
		"empty secret":       {&fakeCreds{}, "\n\n", []string{"-dir", t.TempDir(), "a"}},
		"two piped":          {&fakeCreds{}, "x", []string{"-dir", t.TempDir(), "a", "b"}},
		"too large":          {&fakeCreds{}, strings.Repeat("x", maxSecretBytes+1), []string{"-dir", t.TempDir(), "a"}},
		"systemd-creds fail": {&fakeCreds{fail: errors.New("TPM2 not available")}, "x", []string{"-dir", t.TempDir(), "a"}},
	} {
		code, out, errOut := runCredsCmd(t, tc.f, tc.stdin, tc.args...)
		if code != exitUsage {
			t.Errorf("%s: exit %d", name, code)
		}
		if strings.Contains(out, "LoadCredentialEncrypted") {
			t.Errorf("%s: printed a credential line:\n%s", name, out)
		}
		_ = errOut
	}
	// A directory another account can write in, or a link, is refused
	// before any secret is read.
	open := t.TempDir()
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{open, link} {
		f := &fakeCreds{}
		if code, _, errOut := runCredsCmd(t, f, "x", "-dir", dir, "a"); code != exitUsage || len(f.secrets) != 0 || !strings.Contains(errOut, "only its owner") {
			t.Errorf("%s: exit %d, %q", dir, code, errOut)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(existing, "webhook_secret")); string(b) != "old" {
		t.Error("an existing credential was replaced without -force")
	}
	// A failed encryption leaves no temporary file.
	dir := t.TempDir()
	runCredsCmd(t, &fakeCreds{fail: errors.New("boom")}, "x", "-dir", dir, "a")
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("left behind %v", entries)
	}
	// -force replaces.
	if code, _, errOut := runCredsCmd(t, &fakeCreds{}, "new", "-dir", existing, "-force", "webhook_secret"); code != exitOK {
		t.Errorf("-force: %d, %q", code, errOut)
	}
}

// Fail closed: while the process could still write a core file, no secret is
// read, not even the first byte of stdin, and nothing is encrypted.
func TestSetupCredentialsRefusesWhileCoreDumpsAreOn(t *testing.T) {
	f := &fakeCreds{coreErr: errors.New("prctl: operation not permitted")}
	stdin := &countingReader{r: strings.NewReader("s3cret")}
	var out, errOut bytes.Buffer
	code := runSetupCredentials(context.Background(), []string{"-dir", t.TempDir(), "a"}, stdin, &out, &errOut, f.host())
	if code != exitUsage || !strings.Contains(errOut.String(), "disable core dumps") || strings.Contains(errOut.String(), "s3cret") {
		t.Errorf("exit %d, %q", code, errOut.String())
	}
	if stdin.reads != 0 || len(f.secrets) != 0 || f.locked {
		t.Errorf("stdin read %d times, %d secrets encrypted, memory locked %v", stdin.reads, len(f.secrets), f.locked)
	}
}

type countingReader struct {
	r     *strings.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	return c.r.Read(p)
}

// A piped secret is read into one buffer allocated up front: it is never
// copied into a slice that grows, and wiping the buffers leaves no byte of
// it anywhere.
func TestSecretReaderKeepsOneBufferAndWipesIt(t *testing.T) {
	secret := strings.Repeat("k", 40_000) + "\r\n"
	in := &secretReader{r: strings.NewReader(secret)}
	dst := newSecretBuf()
	base := &dst.b[0]
	if err := in.all(dst); err != nil {
		t.Fatal(err)
	}
	if &dst.b[0] != base || len(dst.b) != maxSecretBytes+1 {
		t.Error("the secret buffer was reallocated")
	}
	if got := bytes.TrimRight(dst.bytes(), "\r\n"); len(got) != 40_000 || got[0] != 'k' {
		t.Fatalf("read %d bytes", len(got))
	}
	in.wipe()
	dst.wipe()
	for i, b := range dst.b {
		if b != 0 {
			t.Fatalf("byte %d of the secret buffer survives a wipe", i)
		}
	}
	if !bytes.Equal(in.buf[:], make([]byte, len(in.buf))) {
		t.Error("the input buffer survives a wipe")
	}
}

func TestSecretReaderLines(t *testing.T) {
	long := strings.Repeat("x", 10_000) // longer than the input buffer
	in := &secretReader{r: strings.NewReader("one\r\ntwo\n" + long + "\nlast")}
	dst := newSecretBuf()
	for i, want := range []string{"one", "two", long, "last"} {
		if err := in.line(dst); err != nil || string(dst.bytes()) != want {
			t.Fatalf("line %d: %q, %v", i, truncate(dst.bytes()), err)
		}
	}
	if err := in.line(dst); !errors.Is(err, io.EOF) {
		t.Errorf("past the end: %v", err)
	}

	atMax := strings.Repeat("y", maxSecretBytes)
	if err := (&secretReader{r: strings.NewReader(atMax + "\n")}).line(dst); err != nil || dst.n != maxSecretBytes {
		t.Errorf("a secret of exactly %d bytes: %d, %v", maxSecretBytes, dst.n, err)
	}
	if err := (&secretReader{r: strings.NewReader(atMax + "y\n")}).line(dst); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("one byte more: %v", err)
	}
	if err := (&secretReader{r: strings.NewReader(atMax + "y")}).all(dst); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("piped, one byte more: %v", err)
	}
}

func truncate(b []byte) string {
	if len(b) > 20 {
		return string(b[:20]) + "..."
	}
	return string(b)
}
