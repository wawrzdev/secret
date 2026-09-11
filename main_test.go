package main

import "testing"

func TestDefaultVersion(t *testing.T) {
	if version != "dev" {
		t.Fatalf("default version = %q, want dev", version)
	}
}
