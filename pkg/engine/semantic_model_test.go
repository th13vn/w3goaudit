package engine

import (
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestAccessPathKeySeparatesFieldsAndTuplePositions(t *testing.T) {
	root := accessRoot{RefID: "fn:param:request", Storage: storageCalldata}
	target := accessPath{Root: root, Segments: []pathSegment{{Kind: segmentField, Name: "target"}}}
	payload := accessPath{Root: root, Segments: []pathSegment{{Kind: segmentField, Name: "payload"}}}
	tuple0 := accessPath{Root: root, Segments: []pathSegment{{Kind: segmentTuple, Index: 0}}}
	tuple1 := accessPath{Root: root, Segments: []pathSegment{{Kind: segmentTuple, Index: 1}}}
	if target.Key() == payload.Key() || tuple0.Key() == tuple1.Key() {
		t.Fatal("independent access paths collapsed")
	}
}

func TestAccessPathKeyIsStableAndCollisionSafe(t *testing.T) {
	for _, separator := range []string{"|", ":", ";", ",", "/", "#", "\x00"} {
		left := accessPath{
			Root: accessRoot{RefID: "root" + separator + "value", Storage: storageMemory},
			Segments: []pathSegment{{
				Kind:     segmentMappingKey,
				Name:     "name",
				Index:    -1,
				Key:      "left" + separator + "right",
				AliasSet: "tail",
			}},
		}
		right := accessPath{
			Root: accessRoot{RefID: "root" + separator + "value", Storage: storageMemory},
			Segments: []pathSegment{{
				Kind:     segmentMappingKey,
				Name:     "name",
				Index:    -1,
				Key:      "left",
				AliasSet: "right" + separator + "tail",
			}},
		}

		if left.Key() == right.Key() {
			t.Fatalf("access-path key collided for separator %q", separator)
		}
		equivalent := accessPath{
			Root: accessRoot{RefID: "root" + separator + "value", Storage: storageMemory},
			Segments: []pathSegment{{
				Kind:     segmentMappingKey,
				Name:     "name",
				Index:    -1,
				Key:      "left" + separator + "right",
				AliasSet: "tail",
			}},
		}
		if left.Key() != equivalent.Key() {
			t.Fatalf("access-path key is unstable for separator %q", separator)
		}
		if !left.Equal(equivalent) || left.Equal(right) {
			t.Fatalf("access-path equality disagrees with identity for separator %q", separator)
		}
	}
}

func TestAccessPathEqualIncludesEveryIdentityComponent(t *testing.T) {
	base := accessPath{
		Root: accessRoot{RefID: "root", Storage: storageCalldata},
		Segments: []pathSegment{{
			Kind:     segmentMappingKey,
			Name:     "field",
			Index:    2,
			Key:      "mapping-key",
			AliasSet: "aliases",
		}},
	}
	equivalent := accessPath{
		Root: accessRoot{RefID: "root", Storage: storageCalldata},
		Segments: []pathSegment{{
			Kind:     segmentMappingKey,
			Name:     "field",
			Index:    2,
			Key:      "mapping-key",
			AliasSet: "aliases",
		}},
	}
	if !base.Equal(equivalent) {
		t.Fatal("independently allocated equivalent paths are not equal")
	}

	cases := []struct {
		name   string
		mutate func(*accessPath)
	}{
		{name: "root ref", mutate: func(path *accessPath) { path.Root.RefID = "other" }},
		{name: "storage", mutate: func(path *accessPath) { path.Root.Storage = storageMemory }},
		{name: "segment count", mutate: func(path *accessPath) {
			path.Segments = append(path.Segments, pathSegment{Kind: segmentTuple})
		}},
		{name: "segment kind", mutate: func(path *accessPath) { path.Segments[0].Kind = segmentField }},
		{name: "segment name", mutate: func(path *accessPath) { path.Segments[0].Name = "other" }},
		{name: "segment index", mutate: func(path *accessPath) { path.Segments[0].Index = 3 }},
		{name: "segment key", mutate: func(path *accessPath) { path.Segments[0].Key = "other" }},
		{name: "segment alias set", mutate: func(path *accessPath) { path.Segments[0].AliasSet = "other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := equivalent
			changed.Segments = append([]pathSegment(nil), equivalent.Segments...)
			tc.mutate(&changed)
			if base.Equal(changed) {
				t.Fatal("distinct access paths compare equal")
			}
		})
	}
}

func TestJoinControlStateNeverFabricatesStrictControl(t *testing.T) {
	cases := []struct{ a, b, want controlState }{
		{controlFixed, controlFixed, controlFixed},
		{controlControlled, controlControlled, controlControlled},
		{controlRestricted, controlRestricted, controlRestricted},
		{controlControlled, controlFixed, controlUnknown},
		{controlDerived, controlControlled, controlUnknown},
	}
	for _, tc := range cases {
		if got := joinControlState(tc.a, tc.b); got != tc.want {
			t.Fatalf("join(%v,%v)=%v want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestSemanticValueCloneDoesNotAliasPaths(t *testing.T) {
	node := &types.ASTNode{Kind: types.KindExprIdentifier, Name: "request"}
	original := semanticValue{
		State: controlDerived,
		Path: &accessPath{
			Root:     accessRoot{RefID: "p", Storage: storageCalldata},
			Segments: []pathSegment{{Kind: segmentField, Name: "target"}},
		},
		Type: types.TypeInfo{
			Name:       "Request calldata",
			BaseName:   "Request",
			Kind:       types.TypeKindStruct,
			Confidence: "high",
		},
		Sources: []accessPath{{
			Root:     accessRoot{RefID: "source", Storage: storageMemory},
			Segments: []pathSegment{{Kind: segmentTuple, Index: 1}},
		}},
		Provenance: semanticRef{
			FunctionID: "file.sol#C.f(Request)",
			ContractID: "file.sol#C",
			File:       "file.sol",
			Node:       node,
			OpIndex:    3,
		},
	}

	cloned := original.Clone()
	if cloned.State != original.State || cloned.Type != original.Type || cloned.Provenance != original.Provenance {
		t.Fatal("semantic value clone did not preserve scalar, type, or provenance values")
	}
	cloned.Path.Segments[0].Name = "payload"
	cloned.Sources[0].Root.RefID = "changed"
	cloned.Sources[0].Segments[0].Index = 9
	if original.Path.Segments[0].Name != "target" ||
		original.Sources[0].Root.RefID != "source" ||
		original.Sources[0].Segments[0].Index != 1 {
		t.Fatal("semantic value clone aliases caller-owned paths")
	}
}

func TestSemanticValueClonePreservesNilAndEmptyPathShapes(t *testing.T) {
	nilClone := (semanticValue{}).Clone()
	if nilClone.Path != nil || nilClone.Sources != nil {
		t.Fatal("semantic value clone changed nil path shapes")
	}

	original := semanticValue{
		Path:    &accessPath{Segments: make([]pathSegment, 0)},
		Sources: make([]accessPath, 0),
	}
	cloned := original.Clone()
	if cloned.Path == nil || cloned.Path.Segments == nil || cloned.Sources == nil {
		t.Fatal("semantic value clone collapsed non-nil empty path shapes")
	}
}

func TestNormalizeAccessPathsSortsAndDeduplicates(t *testing.T) {
	paths := []accessPath{
		{Root: accessRoot{RefID: "b"}, Segments: []pathSegment{{Kind: segmentField, Name: "second"}}},
		{Root: accessRoot{RefID: "a"}, Segments: []pathSegment{{Kind: segmentField, Name: "first"}}},
		{Root: accessRoot{RefID: "b"}, Segments: []pathSegment{{Kind: segmentField, Name: "second"}}},
	}
	got := normalizeAccessPaths(paths)
	if len(got) != 2 || got[0].Root.RefID != "a" || got[1].Root.RefID != "b" {
		t.Fatalf("normalizeAccessPaths() = %+v", got)
	}
	if paths[0].Root.RefID != "b" || paths[1].Root.RefID != "a" || paths[2].Root.RefID != "b" {
		t.Fatal("normalizeAccessPaths reordered caller-owned input")
	}

	got[0].Root.RefID = "changed"
	got[1].Segments[0].Name = "changed"
	if paths[1].Root.RefID != "a" || paths[0].Segments[0].Name != "second" {
		t.Fatal("normalizeAccessPaths returned aliases into caller-owned input")
	}
}

func TestNormalizeAccessPathsCanonicalizesEmptySegmentsDeterministically(t *testing.T) {
	nilSegments := accessPath{Root: accessRoot{RefID: "same"}}
	emptySegments := accessPath{
		Root:     accessRoot{RefID: "same"},
		Segments: make([]pathSegment, 0),
	}
	cases := []struct {
		name  string
		paths []accessPath
	}{
		{name: "nil first", paths: []accessPath{nilSegments, emptySegments}},
		{name: "empty first", paths: []accessPath{emptySegments, nilSegments}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			callerHadEmpty := make([]bool, len(tc.paths))
			for i := range tc.paths {
				callerHadEmpty[i] = tc.paths[i].Segments != nil && len(tc.paths[i].Segments) == 0
			}
			normalized := normalizeAccessPaths(tc.paths)
			if len(normalized) != 1 || normalized[0].Segments != nil {
				t.Fatalf("normalizeAccessPaths() = %+v, want one path with nil segments", normalized)
			}
			for i := range tc.paths {
				if callerHadEmpty[i] && tc.paths[i].Segments == nil {
					t.Fatal("normalizeAccessPaths mutated caller-owned empty segments")
				}
			}
		})
	}
}

func TestNormalizeAccessPathsPreservesOuterShapeAndCanonicalizesEmptySegments(t *testing.T) {
	if normalizeAccessPaths(nil) != nil {
		t.Fatal("normalizeAccessPaths changed a nil input slice")
	}
	if normalizeAccessPaths(make([]accessPath, 0)) == nil {
		t.Fatal("normalizeAccessPaths collapsed a non-nil empty input slice")
	}

	paths := []accessPath{{Segments: make([]pathSegment, 0)}}
	normalized := normalizeAccessPaths(paths)
	if len(normalized) != 1 || normalized[0].Segments != nil {
		t.Fatal("normalizeAccessPaths did not canonicalize empty path segments")
	}
	if paths[0].Segments == nil {
		t.Fatal("normalizeAccessPaths mutated caller-owned empty path segments")
	}
}
