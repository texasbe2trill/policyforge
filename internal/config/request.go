package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/texasbe2trill/policyforge/internal/types"
)

// LoadRequest reads and parses a decision request JSON file.
func LoadRequest(path string) (types.DecisionRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return types.DecisionRequest{}, fmt.Errorf("failed to read request file: %w", err)
	}

	var req types.DecisionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return types.DecisionRequest{}, fmt.Errorf("failed to parse request JSON: %w", err)
	}

	if err := ValidateRequest(req); err != nil {
		return types.DecisionRequest{}, err
	}

	return req, nil
}

// ValidateRequest ensures required fields are present.
func ValidateRequest(req types.DecisionRequest) error {
	missing := make([]string, 0, 5)
	if strings.TrimSpace(req.Subject) == "" {
		missing = append(missing, "subject")
	}
	if strings.TrimSpace(req.Role) == "" {
		missing = append(missing, "role")
	}
	if strings.TrimSpace(req.Resource) == "" {
		missing = append(missing, "resource")
	}
	if strings.TrimSpace(req.Action) == "" {
		missing = append(missing, "action")
	}
	if strings.TrimSpace(string(req.RequestedTier)) == "" {
		missing = append(missing, "requested_tier")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required request fields: %s", strings.Join(missing, ", "))
	}
	return nil
}
