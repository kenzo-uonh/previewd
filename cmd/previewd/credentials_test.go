package main

import (
	"bytes"
	"context"
	"errors"
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
	fail     error
}

func (f *fakeCreds) host() credentialsHost {
	return credentialsHost{
		lockMemory: func() error { f.locked = f.lockErr == nil; return f.lockErr },
		hideInput: func() (func() error, bool, error) {
			if f.terminal {
				f.hidden++
			}
			return func() error { f.hidden--; return nil }, f.terminal, nil
		},
		encrypt: func(_ context.Context, args []string, secret []byte) error {
			if !f.locked {
				return errors.New("memory not locked before a secret was handled")
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
