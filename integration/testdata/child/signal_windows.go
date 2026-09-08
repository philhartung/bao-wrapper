package main

import "fmt"

func waitForSignal(string) error {
	return fmt.Errorf("Unix signal forwarding is not supported on Windows")
}
