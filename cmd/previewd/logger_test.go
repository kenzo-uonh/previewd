package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The daemon's records stay one JSON object per line whatever a logged
// value holds: a line break, a forged record, a carriage return or a
// Unicode line separator in a value, a key or an error is escaped, and
// decodes back to exactly what was logged.
func TestLoggerKeepsHostileValuesInsideTheirRecord(t *testing.T) {
	hostile := "x\n{\"time\":\"2026-01-01T00:00:00Z\",\"level\":\"ERROR\",\"msg\":\"forged\"}\r\u2028\u0000y"
	var out bytes.Buffer
	logger := newLogger(&out)
	logger.Info("Webhook", "login", hostile, hostile, "key", "error", errors.New(hostile))
	logger.With("label", hostile).Warn("Label")

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines for 2 records:\n%s", len(lines), out.String())
	}
	for i, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("line %d is not one JSON record: %v: %q", i, err, line)
		}
		if record["msg"] == "forged" || record["level"] != []string{"INFO", "WARN"}[i] {
			t.Fatalf("line %d: record %v", i, record)
		}
		for _, key := range [][]string{{"login", "error", hostile}, {"label"}}[i] {
			want := hostile
			if key == hostile {
				want = "key"
			}
			if record[key] != want {
				t.Fatalf("line %d: %q = %q, want %q", i, key, record[key], want)
			}
		}
	}
}
