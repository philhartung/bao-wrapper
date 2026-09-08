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
}

type Report struct {
	PID   int
	Files map[string]string
}
