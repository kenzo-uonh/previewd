package secrets

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Injector manages in-memory, air-gapped secret provisioning.
type Injector struct {
	mu      sync.RWMutex
	secrets map[string]string
}

// NewInjector parses a local secrets file and loads key-value pairs strictly into memory.
func NewInjector(filePath string) (*Injector, error) {
	inj := &Injector{
		secrets: make(map[string]string),
	}

	dir := filepath.Dir(filePath)
	base := filepath.Base(filePath)

	root, err := os.OpenRoot(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return inj, nil // Return empty injector if no directory/file is provisioned.
		}
		return nil, fmt.Errorf("failed to open secure root for secrets directory: %w", err)
	}
	defer func() {
		_ = root.Close()
	}()

	file, err := root.Open(base)
	if err != nil {
		if os.IsNotExist(err) {
			return inj, nil
		}
		return nil, fmt.Errorf("failed to securely open secrets file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			inj.secrets[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to parse secrets file: %w", err)
	}

	return inj, nil
}

// GetSecrets returns a copied map of the in-memory secrets for isolated container injection.
func (i *Injector) GetSecrets() map[string]string {
	i.mu.RLock()
	defer i.mu.RUnlock()

	copyMap := make(map[string]string, len(i.secrets))
	maps.Copy(copyMap, i.secrets)
	return copyMap
}
