package orchestrator

// Environment encapsulates the runtime parameters for an ephemeral stack.
type Environment struct {
	ID      string
	Image   string
	Port    int
	Secrets map[string]string // Injected purely into memory; never written to SQLite or disk.
}
