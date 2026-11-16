// Package probe defines the protocol between integration tests and their child.
package probe

type Spec struct {
	Env      map[string]string
	Absent   []string
	Files    map[string]string
	Stdout   string
	Stderr   string
	Input    string
	Args     []string
	ExitCode int
	Signal   bool
	// DelayMillis keeps the child running after it wrote its output and
	// report, before it exits or starts waiting for a signal.
	DelayMillis int
}

type Report struct {
	PID   int
	Files map[string]string
}
