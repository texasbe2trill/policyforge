package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicyValidation(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		expectedError string
	}{
		{
			name: "missing safety_tier name",
			content: `
safety_tiers:
  - requires_approval: true
roles:
  - name: admin
    max_tier: autonomous_write
resources:
  - name: db
`,
			expectedError: "safety_tier at index 0 is missing a name",
		},
		{
			name: "duplicate safety_tier name",
			content: `
safety_tiers:
  - name: read_only
  - name: read_only
roles:
  - name: admin
    max_tier: autonomous_write
resources:
  - name: db
`,
			expectedError: "duplicate safety_tier name found: 'read_only'",
		},
		{
			name: "missing role name",
			content: `
safety_tiers:
  - name: read_only
roles:
  - max_tier: autonomous_write
resources:
  - name: db
`,
			expectedError: "role at index 0 is missing a name",
		},
		{
			name: "duplicate role name",
			content: `
safety_tiers:
  - name: read_only
roles:
  - name: admin
    max_tier: autonomous_write
  - name: admin
    max_tier: read_only
resources:
  - name: db
`,
			expectedError: "duplicate role name found: 'admin'",
		},
		{
			name: "missing resource name",
			content: `
safety_tiers:
  - name: read_only
roles:
  - name: admin
    max_tier: autonomous_write
resources:
  - requires_approval: true
`,
			expectedError: "resource at index 0 is missing a name",
		},
		{
			name: "duplicate resource name",
			content: `
safety_tiers:
  - name: read_only
roles:
  - name: admin
    max_tier: autonomous_write
resources:
  - name: db
  - name: db
`,
			expectedError: "duplicate resource name found: 'db'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, "policy.yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("failed to write policy file: %v", err)
			}

			_, err := LoadPolicy(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != "invalid policy: "+tt.expectedError {
				t.Fatalf("expected error 'invalid policy: %s', got '%v'", tt.expectedError, err)
			}
		})
	}
}
