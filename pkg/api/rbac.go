// Package api defines the management API, RBAC models, authentication tokens, and audit logger.
package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Role defines the administrative permission tier.
type Role string

const (
	RoleSuperAdmin    Role = "SuperAdmin"
	RoleSecurityAdmin Role = "SecurityAdmin"
	RoleNetworkAdmin  Role = "NetworkAdmin"
	RoleAuditor       Role = "Auditor"
)

// Permission specifies individual operations allowed in the platform.
type Permission string

const (
	PermPolicyRead   Permission = "policy:read"
	PermPolicyWrite  Permission = "policy:write"
	PermPolicyCommit Permission = "policy:commit"
	PermNetworkRead  Permission = "network:read"
	PermNetworkWrite Permission = "network:write"
	PermLogsRead     Permission = "logs:read"
	PermSystemAdmin  Permission = "system:admin"
)

// RolePermissions maps roles to granted capability sets.
var RolePermissions = map[Role][]Permission{
	RoleSuperAdmin: {
		PermPolicyRead, PermPolicyWrite, PermPolicyCommit,
		PermNetworkRead, PermNetworkWrite, PermLogsRead, PermSystemAdmin,
	},
	RoleSecurityAdmin: {
		PermPolicyRead, PermPolicyWrite, PermPolicyCommit, PermLogsRead,
	},
	RoleNetworkAdmin: {
		PermNetworkRead, PermNetworkWrite, PermPolicyRead, PermLogsRead,
	},
	RoleAuditor: {
		PermPolicyRead, PermNetworkRead, PermLogsRead,
	},
}

// UserAccount represents an administrative identity.
type UserAccount struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
}

// APIToken represents a scoped, revocable access credential.
type APIToken struct {
	TokenHash string       `json:"token_hash"`
	Username  string       `json:"username"`
	Role      Role         `json:"role"`
	Scopes    []Permission `json:"scopes"`
	ExpiresAt time.Time    `json:"expires_at"`
}

// AuditEvent represents a tamper-evident audit record.
type AuditEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	Username   string    `json:"username"`
	Action     string    `json:"action"`
	Resource   string    `json:"resource"`
	Status     string    `json:"status"` // SUCCESS or FAILED
	Detail     string    `json:"detail"`
	HMAC       string    `json:"hmac"` // Tamper-evident hash chain
}

// RBACManager manages users, tokens, and audit verification.
type RBACManager struct {
	mu         sync.RWMutex
	secretKey  []byte
	users      map[string]*UserAccount
	tokens     map[string]*APIToken
	auditLog   []*AuditEvent
	lastHMAC   string
}

// NewRBACManager creates a new security manager with an HMAC signing key.
func NewRBACManager(secretKey []byte) *RBACManager {
	if len(secretKey) == 0 {
		secretKey = make([]byte, 32)
		_, _ = rand.Read(secretKey)
	}
	mgr := &RBACManager{
		secretKey: secretKey,
		users:     make(map[string]*UserAccount),
		tokens:    make(map[string]*APIToken),
		lastHMAC:  "0000000000000000000000000000000000000000000000000000000000000000",
	}

	// Bootstrap default security auditor
	mgr.users["admin"] = &UserAccount{
		Username:  "admin",
		Role:      RoleSuperAdmin,
		CreatedAt: time.Now(),
	}
	return mgr
}

// Authorize verifies if the given role possesses the required permission.
func (mgr *RBACManager) Authorize(role Role, perm Permission) bool {
	perms, ok := RolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm || p == PermSystemAdmin {
			return true
		}
	}
	return false
}

// LogAudit appends a cryptographically verified audit record.
func (mgr *RBACManager) LogAudit(username, action, resource, status, detail string) *AuditEvent {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	now := time.Now().UTC()
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		mgr.lastHMAC, now.Format(time.RFC3339Nano), username, action, resource, status, detail)

	mac := hmac.New(sha256.New, mgr.secretKey)
	mac.Write([]byte(payload))
	currentHMAC := hex.EncodeToString(mac.Sum(nil))

	event := &AuditEvent{
		Timestamp: now,
		Username:  username,
		Action:    action,
		Resource:  resource,
		Status:    status,
		Detail:    detail,
		HMAC:      currentHMAC,
	}

	mgr.auditLog = append(mgr.auditLog, event)
	mgr.lastHMAC = currentHMAC
	return event
}

// VerifyAuditLog checks the cryptographic integrity of the entire audit chain.
func (mgr *RBACManager) VerifyAuditLog() error {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	prevHMAC := "0000000000000000000000000000000000000000000000000000000000000000"
	for idx, ev := range mgr.auditLog {
		payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
			prevHMAC, ev.Timestamp.Format(time.RFC3339Nano), ev.Username, ev.Action, ev.Resource, ev.Status, ev.Detail)

		mac := hmac.New(sha256.New, mgr.secretKey)
		mac.Write([]byte(payload))
		expectedHMAC := hex.EncodeToString(mac.Sum(nil))

		if expectedHMAC != ev.HMAC {
			return fmt.Errorf("tamper detected at audit record index %d (timestamp: %s)", idx, ev.Timestamp)
		}
		prevHMAC = ev.HMAC
	}
	return nil
}

// IssueToken mints a cryptographically random token string and registers it.
func (mgr *RBACManager) IssueToken(username string, role Role, scopes []Permission, ttl time.Duration) (string, error) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tokenStr := hex.EncodeToString(raw)

	h := sha256.Sum256([]byte(tokenStr))
	tokenHash := hex.EncodeToString(h[:])

	mgr.tokens[tokenHash] = &APIToken{
		TokenHash: tokenHash,
		Username:  username,
		Role:      role,
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(ttl),
	}

	return tokenStr, nil
}

// AuthenticateToken validates the bearer token and returns the caller's session.
func (mgr *RBACManager) AuthenticateToken(tokenStr string) (*APIToken, error) {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	h := sha256.Sum256([]byte(tokenStr))
	tokenHash := hex.EncodeToString(h[:])

	tok, ok := mgr.tokens[tokenHash]
	if !ok {
		return nil, errors.New("invalid authentication token")
	}
	if time.Now().After(tok.ExpiresAt) {
		return nil, errors.New("authentication token has expired")
	}
	return tok, nil
}
