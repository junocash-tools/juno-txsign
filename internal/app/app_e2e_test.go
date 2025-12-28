//go:build e2e

package app

import "testing"

func TestE2E_Smoke(t *testing.T) {
	if Name == "" {
		t.Fatalf("Name is empty")
	}
}

