package main

// previewd setup-credentials (V1.2 spec 3.5): encrypt each secret the daemon
// reads (the webhook secret, the forge token or App key, the listener key,
// the trigger token) as a systemd credential, with systemd-creds encrypt.
// The secret goes from the operator's terminal (echo off) or a pipe to
// systemd-creds' standard input, held in locked memory and cleared after:
// it is never written to a file in the clear, never put on a command line,
// never printed. What lands on disk is the encrypted credential, mode 0600,
// that LoadCredentialEncrypted= decrypts into the unit's private
// $CREDENTIALS_DIRECTORY at start.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/kenzo-uonh/previewd/internal/hardening"
	"github.com/kenzo-uonh/previewd/internal/textutil"
	"github.com/kenzo-uonh/previewd/internal/validate"
)

const (
	// defaultCredstore is where LoadCredentialEncrypted= finds a credential
	// named without a path (systemd.exec(5)).
	defaultCredstore = "/etc/credstore.encrypted" // #nosec G101 -- a directory path, not a credential
	// systemdCreds is the tool that encrypts, by absolute path: never one
	// found on PATH.
	systemdCreds = "/usr/bin/systemd-creds" // #nosec G101 -- the path of a tool, not a credential
	// maxSecretBytes bounds one secret (a PEM private key fits).
	maxSecretBytes = 64 << 10
	// encryptTimeout bounds one systemd-creds run.
	encryptTimeout = time.Minute
)

const credentialsUsage = `usage:
  previewd setup-credentials [-dir DIR] [-with-key KEY] [-force] NAME...
      Encrypt one secret per NAME (a systemd credential name: webhook_secret,
      github-app-key, gitlab-api-token, gitlab-webhook-secret,
      forgejo-api-token, forgejo-webhook-secret, trigger-token, tls-key, or
      the name a *_CREDENTIAL key sets) into DIR/NAME (default ` + defaultCredstore + `)
      with systemd-creds encrypt, mode 0600, then print the
      LoadCredentialEncrypted= line for each (add them with systemctl edit
      previewd). On a terminal each secret is asked twice, without echo; a
      piped secret (a PEM key: < key.pem) is read to its end, for one NAME
      only. Trailing line breaks are dropped (echo adds one; a PEM key does
      not need it). KEY is systemd-creds' --with-key (host, tpm2, host+tpm2, auto;
      default: systemd's). An existing DIR/NAME is refused unless -force.
      Run as root.
`

// credentialsHost is what setup-credentials asks of the machine. Tests
// supply their own.
type credentialsHost struct {
	lockMemory func() error
	// hideInput turns off stdin's echo when it is a terminal.
	hideInput func() (restore func() error, terminal bool, err error)
	// encrypt runs systemd-creds with args, secret on its standard input.
	encrypt func(ctx context.Context, args []string, secret []byte) error
}

func newCredentialsHost() credentialsHost {
	return credentialsHost{
		lockMemory: func() error {
			if err := raiseMemlock(); err != nil {
				return err
			}
			return hardening.LockMemory()
		},
		hideInput: func() (func() error, bool, error) { return hideInput(os.Stdin) },
		encrypt:   runSystemdCreds,
	}
}

// runSystemdCreds runs systemd-creds with args and secret on its standard
// input, in a bare environment. Its diagnostics are quoted bounded; they
// never carry the secret (it is not echoed).
func runSystemdCreds(ctx context.Context, args []string, secret []byte) error {
	ctx, cancel := context.WithTimeout(ctx, encryptTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, systemdCreds, args...) // #nosec G204 -- a fixed binary; args are a validated name, a fixed key set and a path
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.Stdin = bytes.NewReader(secret)
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = io.Discard, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemd-creds encrypt: %w: %s", err, oneLine(textutil.Truncate(stderr.String(), 512)))
	}
	return nil
}

func runSetupCredentials(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, host credentialsHost) int {
	out, diag := &console{w: stdout}, &console{w: stderr}
	code := credentialsCommand(ctx, args, stdin, out, diag, host)
	if code == exitOK && out.err != nil {
		diag.printf("previewd setup-credentials: write: %v\n", out.err)
		return exitUsage
	}
	return code
}

func credentialsCommand(ctx context.Context, args []string, stdin io.Reader, out, diag *console, host credentialsHost) int {
	flags := flag.NewFlagSet("previewd setup-credentials", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("dir", defaultCredstore, "")
	withKey := flags.String("with-key", "", "")
	force := flags.Bool("force", false, "")
	fail := func(format string, a ...any) int {
		diag.printf("previewd setup-credentials: "+format+"\n", a...)
		return exitUsage
	}
	if err := flags.Parse(args); err != nil || flags.NArg() == 0 || cleanAbs("-dir")(*dir) != nil {
		diag.printf("previewd setup-credentials: invalid arguments\n%s", credentialsUsage)
		return exitUsage
	}
	switch *withKey {
	case "", "host", "tpm2", "host+tpm2", "auto":
	default:
		return fail("-with-key %s: want host, tpm2, host+tpm2 or auto", validate.Quote(*withKey))
	}
	names := flags.Args()
	seen := map[string]bool{}
	for _, name := range names {
		if err := validate.CredentialName(name); err != nil {
			return fail("%v", err)
		}
		if seen[name] {
			return fail("%s is named twice", name)
		}
		seen[name] = true
		if _, err := os.Lstat(filepath.Join(*dir, name)); err == nil && !*force {
			return fail("%s exists: pass -force to replace it", filepath.Join(*dir, name))
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fail("%v", err)
		}
	}
	// Secrets are about to be read: memory is locked first, as the daemon's.
	if err := host.lockMemory(); err != nil {
		return fail("lock memory (run as root): %v", err)
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return fail("%v", err)
	}
	// Another account able to write in DIR could put a link where the
	// encrypted file is written: such a directory is refused.
	if fi, err := os.Lstat(*dir); err != nil {
		return fail("%v", err)
	} else if !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
		return fail("%s must be a directory (not a link) that only its owner can write, mode 0700 or 0755", *dir)
	}

	restore, terminal, err := host.hideInput()
	if err != nil {
		return fail("%v", err)
	}
	if !terminal && len(names) != 1 {
		return fail("a piped secret is read to its end: name one credential per run")
	}
	in := bufio.NewReaderSize(stdin, 4096)
	for i, name := range names {
		if terminal && i > 0 {
			if restore, _, err = host.hideInput(); err != nil {
				return fail("%v", err)
			}
		}
		secret, err := readSecret(in, terminal, name, diag)
		if terminal {
			// The echo is back before anything else runs.
			err = errors.Join(err, restore())
		}
		if err != nil {
			clear(secret)
			return fail("%s: %v", name, err)
		}
		err = encryptOne(ctx, host, *dir, name, *withKey, secret)
		clear(secret)
		if err != nil {
			return fail("%s: %v", name, err)
		}
		out.printf("wrote %s\n", filepath.Join(*dir, name))
	}
	out.printf("\nAdd to previewd.service (systemctl edit previewd):\n[Service]\n")
	for _, name := range names {
		out.printf("LoadCredentialEncrypted=%s:%s\n", name, filepath.Join(*dir, name))
	}
	return exitOK
}

// readSecret reads one secret: on a terminal, a line typed twice (both must
// match), without echo; from a pipe, everything up to its end. Empty is
// refused, and so is more than maxSecretBytes.
func readSecret(in *bufio.Reader, terminal bool, name string, diag *console) ([]byte, error) {
	if !terminal {
		data, err := io.ReadAll(io.LimitReader(in, maxSecretBytes+1))
		switch {
		case err != nil:
			clear(data)
			return nil, fmt.Errorf("read the secret: %w", err)
		case len(data) > maxSecretBytes:
			clear(data)
			return nil, fmt.Errorf("the secret exceeds %d bytes", maxSecretBytes)
		}
		secret := bytes.TrimRight(data, "\r\n")
		if len(secret) == 0 {
			clear(data)
			return nil, errors.New("the secret is empty")
		}
		return secret, nil
	}
	diag.printf("%s (input hidden): ", name)
	first, err := readLine(in)
	diag.printf("\n%s again: ", name)
	if err != nil {
		return nil, err
	}
	second, err := readLine(in)
	diag.printf("\n")
	defer clear(second)
	switch {
	case err != nil:
		clear(first)
		return nil, err
	case len(first) == 0:
		return nil, errors.New("the secret is empty")
	case !bytes.Equal(first, second):
		clear(first)
		return nil, errors.New("the two entries differ")
	}
	return first, nil
}

// readLine reads one line without its line break, bounded.
func readLine(in *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, isPrefix, err := in.ReadLine()
		line = append(line, chunk...)
		switch {
		case err != nil:
			clear(line)
			return nil, fmt.Errorf("read the secret: %w", err)
		case len(line) > maxSecretBytes:
			clear(line)
			return nil, fmt.Errorf("the secret exceeds %d bytes", maxSecretBytes)
		case !isPrefix:
			return line, nil
		}
	}
}

// encryptOne encrypts secret into dir/name through a temporary file in dir,
// mode 0600, renamed into place once systemd-creds succeeded.
func encryptOne(ctx context.Context, host credentialsHost, dir, name, withKey string, secret []byte) error {
	target := filepath.Join(dir, name)
	tmp := filepath.Join(dir, "."+name+".previewd-tmp")
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	args := []string{"encrypt", "--name=" + name}
	if withKey != "" {
		args = append(args, "--with-key="+withKey)
	}
	args = append(args, "-", tmp)
	if err := host.encrypt(ctx, args, secret); err != nil {
		return errors.Join(err, removeIfPresent(tmp))
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return errors.Join(err, removeIfPresent(tmp))
	}
	if err := os.Rename(tmp, target); err != nil {
		return errors.Join(err, removeIfPresent(tmp))
	}
	return syncDir(dir)
}

func removeIfPresent(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
