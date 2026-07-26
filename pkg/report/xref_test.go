package report

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// xrefFixtureDB builds a small synthetic database exercising every Phase-A
// declaration kind plus a resolved identifier reference and a located local
// variable declaration.
func xrefFixtureDB() *types.Database {
	db := types.NewDatabase()

	// An identifier occurrence of the state var POOL_MANAGER inside f, plus a
	// local variable declaration `tmp` with a resolved refId.
	local := &types.ASTNode{
		Kind: types.KindDeclVariable, Name: "tmp", RefID: "/x.sol#C.f().tmp",
		StartLine: 5, StartCol: 9, EndLine: 5, EndCol: 12, StartByte: 100, EndByte: 103,
	}
	ident := &types.ASTNode{
		Kind: types.KindExprIdentifier, Name: "POOL_MANAGER", RefID: "/x.sol#C.POOL_MANAGER",
		RefKind: "state_var", StartLine: 6, StartCol: 5, EndLine: 6, EndCol: 17, StartByte: 130, EndByte: 142,
	}
	body := types.NewASTNode(types.KindStmtBlock)
	body.StartLine = 4
	body.AddChildren(local, ident)

	c := &types.Contract{
		ID: "/x.sol#C", Name: "C", Kind: types.ContractKindContract, SourceFile: "/x.sol",
		StartLine: 1, StartCol: 1, EndLine: 20, EndCol: 1,
		StateVariables: []*types.StateVariable{
			{Name: "POOL_MANAGER", TypeName: "address", StartLine: 2, StartCol: 5, EndLine: 2, EndCol: 40},
		},
		Functions: []*types.Function{
			{
				Name: "f", ContractName: "C", SourceFile: "/x.sol", Selector: "f(uint256)",
				Visibility: types.VisibilityExternal, StartLine: 4, StartCol: 5, EndLine: 7, EndCol: 5,
				Parameters: []*types.Parameter{
					{Name: "amount", TypeName: "uint256", StartLine: 4, StartCol: 12, EndLine: 4, EndCol: 26},
				},
				AST: body,
			},
		},
		Events:  []*types.Event{{Name: "Deposited", StartLine: 3, StartCol: 5, EndLine: 3, EndCol: 30}},
		Errors:  []*types.ErrorDef{{Name: "Unauthorized", StartLine: 15, StartCol: 5, EndLine: 15, EndCol: 30}},
		Structs: []*types.Struct{{Name: "Info", StartLine: 8, StartCol: 5, EndLine: 10, EndCol: 5}},
		Enums:   []*types.Enum{{Name: "State", Values: []string{"A", "B"}, StartLine: 11, StartCol: 5, EndLine: 11, EndCol: 30}},
		Modifiers: []*types.Modifier{
			{Name: "onlyOwner", StartLine: 12, StartCol: 5, EndLine: 14, EndCol: 5},
		},
	}
	db.AddContract(c)
	return db
}

func TestBuildXrefJSON_Declarations(t *testing.T) {
	x := BuildXrefJSON(xrefFixtureDB())
	if x.SchemaVersion != SchemaVersion {
		t.Errorf("schemaVersion = %q, want %q", x.SchemaVersion, SchemaVersion)
	}

	byID := map[string]*XrefDecl{}
	for _, d := range x.Declarations {
		if byID[d.ID] != nil {
			t.Fatalf("duplicate declaration id %q", d.ID)
		}
		byID[d.ID] = d
	}

	want := map[string]string{
		"/x.sol#C":                   "contract",
		"/x.sol#C.f(uint256)":        "function",
		"/x.sol#C.f(uint256).amount": "parameter",
		"/x.sol#C.POOL_MANAGER":      "stateVar",
		"/x.sol#C.Deposited":         "event",
		"/x.sol#C.Unauthorized":      "error",
		"/x.sol#C.Info":              "struct",
		"/x.sol#C.State":             "enum",
		"/x.sol#C.onlyOwner":         "modifier",
		"/x.sol#C.f().tmp":           "local",
	}
	for id, kind := range want {
		d := byID[id]
		if d == nil {
			t.Errorf("missing declaration %q", id)
			continue
		}
		if d.Kind != kind {
			t.Errorf("declaration %q kind = %q, want %q", id, d.Kind, kind)
		}
	}

	// Parameter range comes from the parameter's own position fields.
	if p := byID["/x.sol#C.f(uint256).amount"]; p != nil {
		if p.Range.StartLine != 4 || p.Range.StartCol != 12 || p.Range.File != "/x.sol" {
			t.Errorf("parameter range = %+v, want line4 col12 /x.sol", p.Range)
		}
	}
}

func TestBuildXrefJSON_References(t *testing.T) {
	x := BuildXrefJSON(xrefFixtureDB())
	var poolRef *XrefRef
	for _, r := range x.References {
		if r.RefID == "/x.sol#C.POOL_MANAGER" {
			poolRef = r
		}
	}
	if poolRef == nil {
		t.Fatalf("missing POOL_MANAGER reference, got %d refs", len(x.References))
	}
	if poolRef.RefKind != "state_var" {
		t.Errorf("refKind = %q, want state_var", poolRef.RefKind)
	}
	if poolRef.File != "/x.sol" || poolRef.Range.StartLine != 6 || poolRef.Range.StartCol != 5 {
		t.Errorf("reference loc = file=%q %+v, want /x.sol line6 col5", poolRef.File, poolRef.Range)
	}
	// The local declaration is itself also emitted as a reference (it has a refId).
	var sawLocalRef bool
	for _, r := range x.References {
		if r.RefID == "/x.sol#C.f().tmp" {
			sawLocalRef = true
		}
	}
	if !sawLocalRef {
		t.Error("expected the local variable node to appear as a reference")
	}
}

func TestBuildXrefJSON_Deterministic(t *testing.T) {
	first := BuildXrefJSON(xrefFixtureDB())
	second := BuildXrefJSON(xrefFixtureDB())
	fb, _ := json.Marshal(first)
	sb, _ := json.Marshal(second)
	if !reflect.DeepEqual(fb, sb) {
		t.Fatalf("BuildXrefJSON is nondeterministic:\n%s\n%s", fb, sb)
	}
	if !json.Valid(fb) {
		t.Fatal("invalid JSON")
	}
}

func TestBuildXrefJSON_NilDatabase(t *testing.T) {
	x := BuildXrefJSON(nil)
	if x == nil || x.SchemaVersion != SchemaVersion || len(x.Declarations) != 0 {
		t.Fatalf("nil db should yield empty index, got %+v", x)
	}
}
