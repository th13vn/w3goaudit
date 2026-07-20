package types

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIsAccessControlledDoesNotTrustRoleModifierNames(t *testing.T) {
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

			if fn.IsAccessControlled(NewDatabase()) {
				t.Fatalf("modifier name %s must not prove access control", tt.modifier)
			}
		})
	}
}

func TestFunctionCallArgCountJSONPresence(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
	}{
		{name: "missing is unknown", raw: `{"target":"helper","callType":"internal"}`, want: -1},
		{name: "explicit zero", raw: `{"target":"helper","callType":"internal","argCount":0}`, want: 0},
		{name: "positive", raw: `{"target":"helper","callType":"internal","argCount":2}`, want: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var call FunctionCall
			if err := json.Unmarshal([]byte(tc.raw), &call); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}
			if call.ArgCount != tc.want {
				t.Fatalf("ArgCount = %d, want %d", call.ArgCount, tc.want)
			}
		})
	}

	call := FunctionCall{Target: "helper", CallType: CallTypeInternal, ArgCount: 0}
	first, err := json.Marshal(&call)
	if err != nil {
		t.Fatalf("first marshal: %v", err)
	}
	if !bytes.Contains(first, []byte(`"argCount":0`)) {
		t.Fatalf("zero argCount omitted from JSON: %s", first)
	}
	var roundTripped FunctionCall
	if err := json.Unmarshal(first, &roundTripped); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if roundTripped.ArgCount != 0 {
		t.Fatalf("round-trip ArgCount = %d, want 0", roundTripped.ArgCount)
	}
	second, err := json.Marshal(&roundTripped)
	if err != nil {
		t.Fatalf("second marshal: %v", err)
	}
	if !bytes.Contains(second, []byte(`"argCount":0`)) {
		t.Fatalf("zero argCount omitted after second marshal: %s", second)
	}
}

func TestLoadFromJSONMissingFunctionCallArgCountIsUnknown(t *testing.T) {
	db := NewDatabase()
	contract := &Contract{
		Name:       "C",
		SourceFile: "/repo/C.sol",
		Functions: []*Function{{
			Name:         "run",
			ContractName: "C",
			Calls: []*FunctionCall{{
				Target:   "helper",
				CallType: CallTypeInternal,
				ArgCount: 0,
			}},
		}},
	}
	db.AddContract(contract)
	raw, err := json.Marshal(db)
	if err != nil {
		t.Fatalf("marshal database: %v", err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatalf("decode database JSON: %v", err)
	}
	contracts := legacy["contracts"].(map[string]any)
	contractJSON := contracts[contract.ID].(map[string]any)
	functions := contractJSON["functions"].([]any)
	calls := functions[0].(map[string]any)["calls"].([]any)
	delete(calls[0].(map[string]any), "argCount")
	legacyRaw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy database: %v", err)
	}
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, legacyRaw, 0o644); err != nil {
		t.Fatalf("write legacy database: %v", err)
	}

	loaded, err := LoadFromJSON(path)
	if err != nil {
		t.Fatalf("LoadFromJSON: %v", err)
	}
	got := loaded.GetContractByID(contract.ID).Functions[0].Calls[0].ArgCount
	if got != -1 {
		t.Fatalf("legacy missing ArgCount = %d, want -1", got)
	}
}
