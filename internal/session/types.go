package session

// AuthType identifies how a session was established.
type AuthType string

// SessionStatus reflects the lifecycle state of a session.
type SessionStatus string

const (
	AuthTypeLocalToken AuthType = "local_token"
	AuthTypeOIDCStub   AuthType = "oidc_stub"
	AuthTypeAgentToken AuthType = "agent_token"

	SessionActive  SessionStatus = "active"
	SessionExpired SessionStatus = "expired"
	SessionRevoked SessionStatus = "revoked"
)

// Session records a single authenticated session's identity and lifecycle state.
type Session struct {
	SessionID string            `json:"session_id"`
	Subject   string            `json:"subject"`
	Agent     string            `json:"agent,omitempty"`
	Role      string            `json:"role"`
	AuthType  AuthType          `json:"auth_type"`
	IssuedAt  string            `json:"issued_at"`
	ExpiresAt string            `json:"expires_at"`
	CreatedBy string            `json:"created_by,omitempty"`
	Status    SessionStatus     `json:"status"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}
