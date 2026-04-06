package auth

import "context"

type contextKey struct{}

// Identity holds the authenticated identity extracted from a verified request.
type Identity struct {
	Subject         string
	Role            string
	Agent           string
	SessionID       string
	AuthType        string
	SessionIssuedAt string // RFC3339; used for agent TTL enforcement
}

// WithIdentity stores an Identity in the request context.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// GetIdentity retrieves the Identity from a context.
// Returns the zero Identity and false if not present.
func GetIdentity(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(Identity)
	return id, ok
}
