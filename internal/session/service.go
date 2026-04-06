package session

import (
	"fmt"
	"time"
)

const (
	DefaultUserTTL  = 60 * time.Minute
	DefaultAgentTTL = 30 * time.Minute
)

// Create persists a new active session and returns it.
func Create(subject, role, agentName string, authType AuthType, ttl time.Duration) (*Session, error) {
	now := time.Now().UTC()
	s := Session{
		SessionID: newID(),
		Subject:   subject,
		Role:      role,
		Agent:     agentName,
		AuthType:  authType,
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(ttl).Format(time.RFC3339),
		Status:    SessionActive,
	}
	if err := create(s); err != nil {
		return nil, fmt.Errorf("failed to persist session: %w", err)
	}
	return &s, nil
}

// FindActive returns the most recently created active (non-expired, non-revoked)
// session for the given subject and auth type, or nil if none exists.
// A revoked session returns an error (explicit security action — deny access).
// An expired session is skipped so the caller can create a fresh one.
func FindActive(subject string, authType AuthType) (*Session, error) {
	sessions, err := loadAll()
	if err != nil {
		return nil, err
	}
	// Iterate in reverse so we check the newest matching session first.
	for i := len(sessions) - 1; i >= 0; i-- {
		s := &sessions[i]
		if s.Subject != subject || s.AuthType != authType {
			continue
		}
		if s.Status == SessionRevoked {
			return nil, fmt.Errorf("session revoked for subject '%s'", subject)
		}
		if IsExpired(s) {
			// Expired sessions are not an error — skip and let a new one be created.
			continue
		}
		return s, nil
	}
	return nil, nil
}

// Validate retrieves a session by ID and verifies it is active and not expired.
func Validate(sessionID string) (*Session, error) {
	s, err := get(sessionID)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("session '%s' not found", sessionID)
	}
	if s.Status == SessionRevoked {
		return nil, fmt.Errorf("session '%s' has been revoked", sessionID)
	}
	if IsExpired(s) {
		return nil, fmt.Errorf("session '%s' has expired", sessionID)
	}
	return s, nil
}

// IsExpired reports whether the session's ExpiresAt time has passed.
func IsExpired(s *Session) bool {
	if s.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, s.ExpiresAt)
	if err != nil {
		return false
	}
	return time.Now().UTC().After(t)
}

// Revoke marks a session as revoked.
func Revoke(sessionID string) error {
	return revoke(sessionID)
}

// List returns all sessions.
func List() ([]Session, error) {
	return listAll()
}
