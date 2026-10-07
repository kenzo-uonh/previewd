package secrets

import (
	"testing"
)

func TestClassifyStagingFS(t *testing.T) {
	const ext4Magic int64 = 0xef53

	cases := []struct {
		name       string
		magic      int64
		allowTmpfs bool
		wantErr    bool
	}{
		{"ramfs", ramfsMagic, false, false},
		{"tmpfs refused by default", tmpfsMagic, false, true},
		{"tmpfs with explicit opt-in", tmpfsMagic, true, false},
		{"disk refused", ext4Magic, false, true},
		{"disk refused even with tmpfs opt-in", ext4Magic, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyStagingFS(tc.magic, tc.allowTmpfs)
			if (err != nil) != tc.wantErr {
				t.Fatalf("classifyStagingFS(%#x, %v) error = %v, wantErr %v", tc.magic, tc.allowTmpfs, err, tc.wantErr)
			}
		})
	}
}

func TestNewStagerRefusesDiskBackedTempDir(t *testing.T) {
	root := stagingRoot(t)
	magic, err := statfsMagic(root)
	if err != nil {
		t.Fatal(err)
	}
	if magic == ramfsMagic || magic == tmpfsMagic {
		t.Skipf("test temp dir is memory-backed (%#x); disk refusal not observable here", magic)
	}
	if _, err := NewStager(root, true); err == nil {
		t.Fatalf("NewStager accepted a disk-backed directory (magic %#x)", magic)
	}
}
