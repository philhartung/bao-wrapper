//go:build integration

package integration

import "testing"

func runSignalTests(t *testing.T, _ *suite) {
	t.Run("unix-signals", func(t *testing.T) {
		t.Skip("Unix signal forwarding is not supported on Windows")
	})
}
