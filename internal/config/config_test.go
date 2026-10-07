package config

import "testing"

// Limits fail closed: a malformed value is a configuration error, never a
// silent fallback to the default.
func TestPositiveInt(t *testing.T) {
	const name = "PREVIEWD_TEST_LIMIT"

	t.Setenv(name, "")
	if n, err := positiveInt(name, 512); err != nil || n != 512 {
		t.Fatalf("unset = %d, %v; want default 512", n, err)
	}
	t.Setenv(name, "1024")
	if n, err := positiveInt(name, 512); err != nil || n != 1024 {
		t.Fatalf("1024 = %d, %v", n, err)
	}
	for _, bad := range []string{"0", "-1", "abc", "1.5", " 64", "64MiB", "1099511627777", "9223372036854775808"} {
		t.Setenv(name, bad)
		if n, err := positiveInt(name, 512); err == nil {
			t.Errorf("%q accepted as %d", bad, n)
		}
	}
}
