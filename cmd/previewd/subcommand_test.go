package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each Day-2 command is reachable from the binary's argv and fails with its
// own usage error, not as an unknown command and not by starting the
// daemon, when its arguments are wrong.
func TestSubcommandDispatch(t *testing.T) {
	savedArgs, savedStderr := os.Args, os.Stderr
	t.Cleanup(func() { os.Args, os.Stderr = savedArgs, savedStderr })

	for _, tc := range []struct {
		args    []string
		unknown bool
		usage   string
	}{
		{[]string{"previewd", "doctor", "-no-such-flag"}, false, "previewd doctor"},
		{[]string{"previewd", "backup"}, false, "previewd backup"},
		{[]string{"previewd", "restore"}, false, "previewd restore"},
		{[]string{"previewd", "no-such-command"}, true, "previewd doctor"}, // the usage lists them
	} {
		f, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
		if err != nil {
			t.Fatal(err)
		}
		os.Args, os.Stderr = tc.args, f
		code, ran := subcommand()
		os.Stderr = savedStderr
		out, readErr := os.ReadFile(f.Name())
		if err := errorsJoin(f.Close(), readErr); err != nil {
			t.Fatal(err)
		}
		if !ran || code != exitUsage {
			t.Errorf("%v: code %d, ran %v; want exit %d without starting the daemon", tc.args, code, ran, exitUsage)
		}
		if got := strings.Contains(string(out), "unknown command"); got != tc.unknown {
			t.Errorf("%v: stderr %q; unknown command reported = %v, want %v", tc.args, out, got, tc.unknown)
		}
		if !strings.Contains(string(out), tc.usage) {
			t.Errorf("%v: stderr %q lacks %q", tc.args, out, tc.usage)
		}
	}
	os.Args = []string{"previewd"}
	if _, ran := subcommand(); ran {
		t.Error("no argument must start the daemon")
	}
}

func errorsJoin(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
