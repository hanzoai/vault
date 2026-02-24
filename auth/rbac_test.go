package auth

import "testing"

func TestAuthorize(t *testing.T) {
	tests := []struct {
		role   Role
		op     Operation
		expect bool
	}{
		// Tokenizer
		{RoleTokenizer, OpTokenize, true},
		{RoleTokenizer, OpMetadata, true},
		{RoleTokenizer, OpDelete, true},
		{RoleTokenizer, OpDetokenize, false},
		{RoleTokenizer, OpRotate, false},
		{RoleTokenizer, OpKeyGenerate, false},

		// Operator
		{RoleOperator, OpTokenize, true},
		{RoleOperator, OpDetokenize, true},
		{RoleOperator, OpDelete, true},
		{RoleOperator, OpRotate, true},
		{RoleOperator, OpMetadata, true},
		{RoleOperator, OpKeyGenerate, false},

		// Key Admin
		{RoleKeyAdmin, OpKeyGenerate, true},
		{RoleKeyAdmin, OpKeyRotate, true},
		{RoleKeyAdmin, OpKeyDestroy, true},
		{RoleKeyAdmin, OpTokenize, false},
		{RoleKeyAdmin, OpDetokenize, false},

		// Auditor
		{RoleAuditor, OpAuditRead, true},
		{RoleAuditor, OpTokenize, false},
		{RoleAuditor, OpDetokenize, false},

		// Unknown role
		{Role("unknown"), OpTokenize, false},
	}

	for _, tt := range tests {
		err := Authorize(tt.role, tt.op)
		if tt.expect && err != nil {
			t.Errorf("Authorize(%s, %s) should succeed, got %v", tt.role, tt.op, err)
		}
		if !tt.expect && err == nil {
			t.Errorf("Authorize(%s, %s) should fail", tt.role, tt.op)
		}
	}
}
