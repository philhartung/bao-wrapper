//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func waitForSignal(report string) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	if err := os.WriteFile(report+".ready", []byte("ready"), 0600); err != nil {
		return err
	}
	select {
	case sig := <-signals:
		if err := os.WriteFile(report+".signal", []byte(sig.String()), 0600); err != nil {
			return err
		}
	case <-time.After(10 * time.Second):
		return fmt.Errorf("signal never arrived")
	}
	// Remain alive until the parent has checked cleanup and revocation.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(report + ".release"); err == nil {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("signal child was not released")
}
