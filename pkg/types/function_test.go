package types

import "testing"

func TestIsAccessControlledRecognizesRoleModifiers(t *testing.T) {
	tests := []struct {
		name     string
		modifier string
	}{
		{name: "operator", modifier: "onlyOperator"},
		{name: "governance", modifier: "onlyGovernance"},
		{name: "guardian", modifier: "onlyGuardian"},
		{name: "manager", modifier: "onlyManager"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := &Function{
				Name:      "guarded",
				Modifiers: []string{tt.modifier},
			}

			if !fn.IsAccessControlled(NewDatabase()) {
				t.Fatalf("expected %s to be treated as access control", tt.modifier)
			}
		})
	}
}
