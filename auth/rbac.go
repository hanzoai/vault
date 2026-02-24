// Package auth provides authentication and authorization for the vault service.
package auth

import (
	"errors"
)

var (
	ErrUnauthorized = errors.New("vault/auth: unauthorized")
	ErrForbidden    = errors.New("vault/auth: forbidden")
)

// Role defines access levels for vault operations.
type Role string

const (
	// RoleTokenizer can tokenize and get metadata. Cannot detokenize.
	RoleTokenizer Role = "tokenizer"

	// RoleOperator can tokenize, detokenize, and manage cards.
	RoleOperator Role = "operator"

	// RoleKeyAdmin can manage encryption keys. Cannot access card data.
	RoleKeyAdmin Role = "key_admin"

	// RoleAuditor can read audit logs. Cannot access card data or keys.
	RoleAuditor Role = "auditor"
)

// Operation defines a vault operation that requires authorization.
type Operation string

const (
	OpTokenize    Operation = "tokenize"
	OpDetokenize  Operation = "detokenize"
	OpDelete      Operation = "delete"
	OpRotate      Operation = "rotate"
	OpMetadata    Operation = "metadata"
	OpKeyGenerate Operation = "key_generate"
	OpKeyRotate   Operation = "key_rotate"
	OpKeyDestroy  Operation = "key_destroy"
	OpAuditRead   Operation = "audit_read"
)

// permissions maps roles to allowed operations.
var permissions = map[Role]map[Operation]bool{
	RoleTokenizer: {
		OpTokenize: true,
		OpMetadata: true,
		OpDelete:   true,
	},
	RoleOperator: {
		OpTokenize:   true,
		OpDetokenize: true,
		OpDelete:     true,
		OpRotate:     true,
		OpMetadata:   true,
	},
	RoleKeyAdmin: {
		OpKeyGenerate: true,
		OpKeyRotate:   true,
		OpKeyDestroy:  true,
	},
	RoleAuditor: {
		OpAuditRead: true,
	},
}

// Authorize checks if a role is allowed to perform an operation.
func Authorize(role Role, op Operation) error {
	ops, ok := permissions[role]
	if !ok {
		return ErrForbidden
	}
	if !ops[op] {
		return ErrForbidden
	}
	return nil
}

// Identity represents an authenticated caller.
type Identity struct {
	Subject  string `json:"sub"`       // service or user ID
	TenantId string `json:"tenantId"`  // which tenant
	Role     Role   `json:"role"`      // RBAC role
}
