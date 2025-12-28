//go:build integration

package app

import "testing"

func TestIntegration_Smoke(t *testing.T) {
	if Name == "" {
		t.Fatalf("Name is empty")
	}
}
