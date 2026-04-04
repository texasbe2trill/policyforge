package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRequest(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "request.json")
	content := `{"subject":"chris","role":"operator","resource":"prod/payment-service","action":"restart","requested_tier":"supervised_write"}`

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp request: %v", err)
	}

	req, err := LoadRequest(path)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if req.Subject != "chris" || req.Role != "operator" || req.Resource != "prod/payment-service" || req.Action != "restart" || string(req.RequestedTier) != "supervised_write" {
		t.Fatalf("unexpected request loaded: %+v", req)
	}
}

func TestLoadRequestMissingRequiredField(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "request.json")
	content := `{"subject":"","role":"operator","resource":"prod/payment-service","action":"restart","requested_tier":"supervised_write"}`

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp request: %v", err)
	}

	_, err := LoadRequest(path)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "missing required request fields") {
		t.Fatalf("unexpected error: %v", err)
	}
}
