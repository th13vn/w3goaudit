package engine

import (
	"sort"
	"strconv"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/types"
)

type controlState uint8

const (
	controlUnknown controlState = iota
	controlFixed
	controlRestricted
	controlDerived
	controlControlled
)

type storageClass uint8

const (
	storageUnknown storageClass = iota
	storageStack
	storageMemory
	storageCalldata
	storagePersistent
	storageReturn
)

type segmentKind uint8

const (
	segmentField segmentKind = iota + 1
	segmentTuple
	segmentFixedIndex
	segmentDynamicIndex
	segmentMappingKey
	segmentMemoryOffset
)

type accessRoot struct {
	RefID   string
	Storage storageClass
}

type pathSegment struct {
	Kind     segmentKind
	Name     string
	Index    int
	Key      string
	AliasSet string
}

type accessPath struct {
	Root     accessRoot
	Segments []pathSegment
}

func (p accessPath) Key() string {
	var key strings.Builder
	key.WriteString("access-path:1;")
	appendAccessPathString(&key, p.Root.RefID)
	appendAccessPathInt(&key, int64(p.Root.Storage))
	appendAccessPathInt(&key, int64(len(p.Segments)))
	for _, segment := range p.Segments {
		appendAccessPathInt(&key, int64(segment.Kind))
		appendAccessPathString(&key, segment.Name)
		appendAccessPathInt(&key, int64(segment.Index))
		appendAccessPathString(&key, segment.Key)
		appendAccessPathString(&key, segment.AliasSet)
	}
	return key.String()
}

func (p accessPath) Equal(other accessPath) bool {
	return p.Key() == other.Key()
}

func appendAccessPathString(key *strings.Builder, value string) {
	key.WriteString(strconv.Itoa(len(value)))
	key.WriteByte(':')
	key.WriteString(value)
	key.WriteByte(';')
}

func appendAccessPathInt(key *strings.Builder, value int64) {
	key.WriteString(strconv.FormatInt(value, 10))
	key.WriteByte(';')
}

type semanticRef struct {
	FunctionID string
	ContractID string
	File       string
	Node       *types.ASTNode
	OpIndex    int
}

type semanticValue struct {
	State      controlState
	Path       *accessPath
	Type       types.TypeInfo
	Sources    []accessPath
	Provenance semanticRef
}

func (value semanticValue) Clone() semanticValue {
	cloned := value
	if value.Path != nil {
		path := cloneAccessPath(*value.Path)
		cloned.Path = &path
	}
	if value.Sources != nil {
		cloned.Sources = make([]accessPath, len(value.Sources))
		for i := range value.Sources {
			cloned.Sources[i] = cloneAccessPath(value.Sources[i])
		}
	}
	return cloned
}

func cloneAccessPath(path accessPath) accessPath {
	cloned := path
	if path.Segments != nil {
		cloned.Segments = make([]pathSegment, len(path.Segments))
		copy(cloned.Segments, path.Segments)
	}
	return cloned
}

func normalizeAccessPaths(paths []accessPath) []accessPath {
	if paths == nil {
		return nil
	}

	type keyedPath struct {
		key  string
		path accessPath
	}
	keyed := make([]keyedPath, len(paths))
	for i := range paths {
		path := cloneAccessPath(paths[i])
		if len(path.Segments) == 0 {
			path.Segments = nil
		}
		keyed[i] = keyedPath{key: path.Key(), path: path}
	}
	sort.Slice(keyed, func(i, j int) bool {
		return keyed[i].key < keyed[j].key
	})

	normalized := make([]accessPath, 0, len(keyed))
	var previous string
	for i, entry := range keyed {
		if i > 0 && entry.key == previous {
			continue
		}
		normalized = append(normalized, entry.path)
		previous = entry.key
	}
	return normalized
}

func joinControlState(left, right controlState) controlState {
	if left == right {
		return left
	}
	return controlUnknown
}

type semanticOpKind uint8

const (
	semanticOpUnknown semanticOpKind = iota
	semanticOpRead
	semanticOpWrite
	semanticOpAssign
	semanticOpCall
	semanticOpCheck
	semanticOpReturn
	semanticOpTerminal
)

type semanticOp struct {
	ID         int
	Kind       semanticOpKind
	Provenance semanticRef
	Reads      []accessPath
	Writes     []accessPath
	Inputs     []semanticValue
}

type semanticFunction struct {
	Function   *types.Function
	Contract   *types.Contract
	Operations []*semanticOp
	ByNode     map[*types.ASTNode][]int
}
