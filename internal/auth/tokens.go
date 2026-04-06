package auth

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// TokenEntry maps a static bearer token to an authenticated identity.
type TokenEntry struct {
	Token    string `yaml:"token"`
	Subject  string `yaml:"subject"`
	Role     string `yaml:"role"`
	Agent    string `yaml:"agent,omitempty"`
	AuthType string `yaml:"auth_type"`
}

type tokenConfig struct {
	Tokens []TokenEntry `yaml:"tokens"`
}

// TokenStore provides O(1) lookup of token entries by token value.
type TokenStore struct {
	lookup map[string]TokenEntry
}

// LoadTokens reads a tokens YAML file and returns a TokenStore.
func LoadTokens(path string) (*TokenStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read token config: %w", err)
	}
	var cfg tokenConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse token config: %w", err)
	}
	ts := &TokenStore{lookup: make(map[string]TokenEntry, len(cfg.Tokens))}
	for _, t := range cfg.Tokens {
		ts.lookup[t.Token] = t
	}
	return ts, nil
}

// Lookup returns the TokenEntry for the given token value, or (zero, false).
func (ts *TokenStore) Lookup(token string) (TokenEntry, bool) {
	e, ok := ts.lookup[token]
	return e, ok
}

// NewTokenStoreFromEntries creates a TokenStore directly from a slice of entries.
// Useful for testing without disk I/O.
func NewTokenStoreFromEntries(entries []TokenEntry) *TokenStore {
	ts := &TokenStore{lookup: make(map[string]TokenEntry, len(entries))}
	for _, e := range entries {
		ts.lookup[e.Token] = e
	}
	return ts
}
