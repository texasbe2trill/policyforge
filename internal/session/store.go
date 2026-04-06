package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// storePath is a var (not const) so tests can redirect to a temp path.
var storePath = "artifacts/sessions.json"

// StorePath returns the current session store path.
func StorePath() string { return storePath }

// SetStorePath overrides the store path (used in tests).
func SetStorePath(p string) { storePath = p }

// create appends a session record atomically.
func create(s Session) error {
	sessions, err := loadAll()
	if err != nil {
		return err
	}
	sessions = append(sessions, s)
	return saveAll(sessions)
}

// get returns the session with the given ID, or nil if not found.
func get(sessionID string) (*Session, error) {
	sessions, err := loadAll()
	if err != nil {
		return nil, err
	}
	for i := range sessions {
		if sessions[i].SessionID == sessionID {
			return &sessions[i], nil
		}
	}
	return nil, nil
}

// listAll returns all sessions.
func listAll() ([]Session, error) {
	return loadAll()
}

// revoke marks a session as revoked.
func revoke(sessionID string) error {
	sessions, err := loadAll()
	if err != nil {
		return err
	}
	found := false
	for i := range sessions {
		if sessions[i].SessionID == sessionID {
			sessions[i].Status = SessionRevoked
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("session '%s' not found", sessionID)
	}
	return saveAll(sessions)
}

// newID generates a unique session ID.
func newID() string {
	return fmt.Sprintf("sess-%d", time.Now().UTC().UnixNano())
}

func loadAll() ([]Session, error) {
	data, err := os.ReadFile(storePath)
	if os.IsNotExist(err) {
		return []Session{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read session store: %w", err)
	}
	var sessions []Session
	if err := json.Unmarshal(data, &sessions); err != nil {
		return nil, fmt.Errorf("failed to parse session store: %w", err)
	}
	return sessions, nil
}

func saveAll(sessions []Session) error {
	if err := os.MkdirAll(filepath.Dir(storePath), 0o755); err != nil {
		return fmt.Errorf("failed to create session store directory: %w", err)
	}
	data, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sessions: %w", err)
	}
	tmp := storePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("failed to write session store: %w", err)
	}
	return os.Rename(tmp, storePath)
}
