package app

import "testing"

func TestName_NotEmpty(t *testing.T) {
	if Name == "" {
		t.Fatalf("Name is empty")
	}
}

