package builder

import (
	"fmt"
	"strings"

	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func (b *ASTBuilder) typeInfoFromTypeName(typeName, source string) types.TypeInfo {
	return resolveTypeInfo(typeName, source, b.db, b.contract)
}

func (cgb *CallGraphBuilder) typeInfoFromTypeName(typeName, source string) types.TypeInfo {
	if cgb == nil {
		return types.TypeInfo{}
	}
	var contract *types.Contract
	if cgb.db != nil && cgb.currentContract != "" {
		contract = cgb.db.GetContractByName(cgb.currentContract)
	}
	return resolveTypeInfo(typeName, source, cgb.db, contract)
}

func resolveTypeInfo(typeName, source string, db *types.Database, contract *types.Contract) types.TypeInfo {
	clean := types.CleanTypeName(typeName)
	if clean == "" || clean == "unknown" {
		return types.TypeInfo{}
	}

	isPayable := strings.Contains(clean, "payable")
	baseName := baseTypeName(clean)
	ti := types.TypeInfo{
		Name:       clean,
		BaseName:   baseName,
		Kind:       types.TypeKindUnknown,
		IsPayable:  isPayable,
		Confidence: "low",
		Source:     source,
	}

	if keyType, valueType, ok := parseMappingType(clean); ok {
		ti.Kind = types.TypeKindMapping
		ti.KeyType = keyType
		ti.ValueType = valueType
		ti.Confidence = "medium"
		return ti
	}

	if element := parseArrayElementType(clean); element != "" {
		ti.Kind = types.TypeKindArray
		ti.ElementType = element
		ti.Confidence = "medium"
		return ti
	}

	if isPrimitiveTypeName(baseName) {
		ti.Kind = types.TypeKindPrimitive
		ti.IsAddress = baseName == "address"
		ti.Confidence = "high"
		return ti
	}

	if db != nil {
		if c := db.GetContractByName(baseName); c != nil {
			ti.Kind = string(c.Kind)
			ti.ContractID = c.ID
			ti.Confidence = "high"
			return ti
		}
		if contract != nil {
			for _, st := range contract.Structs {
				if st.Name == baseName {
					ti.Kind = types.TypeKindStruct
					ti.ContractID = contract.ID
					ti.Confidence = "high"
					return ti
				}
			}
		}
	}

	return ti
}

func (b *ASTBuilder) expressionType(expr ast.Node) types.TypeInfo {
	if expr == nil {
		return types.TypeInfo{}
	}

	switch e := expr.(type) {
	case *ast.Identifier:
		if ti, ok := b.symbolTypes[e.Name]; ok {
			return ti
		}
		if e.Name == "this" && b.contract != nil {
			return b.typeInfoFromTypeName(b.contract.Name, "this")
		}
		if e.Name == "super" && b.contract != nil {
			return b.typeInfoFromTypeName(b.contract.Name, "super")
		}
		if isPrimitiveTypeName(e.Name) || b.isKnownUserType(e.Name) {
			return b.typeInfoFromTypeName(e.Name, "type_identifier")
		}

	case *ast.ElementaryTypeName:
		return b.typeInfoFromTypeName(e.Name, "type_identifier")

	case *ast.UserDefinedTypeName:
		return b.typeInfoFromTypeName(e.NamePath, "type_identifier")

	case *ast.FunctionCall:
		switch callee := e.Expression.(type) {
		case *ast.ElementaryTypeName:
			return b.typeInfoFromTypeName(callee.Name, "type_cast")
		case *ast.UserDefinedTypeName:
			return b.typeInfoFromTypeName(callee.NamePath, "type_cast")
		case *ast.Identifier:
			if callee.Name == "payable" {
				return b.typeInfoFromTypeName("address payable", "payable_cast")
			}
			if isPrimitiveTypeName(callee.Name) || b.isKnownUserType(callee.Name) {
				return b.typeInfoFromTypeName(callee.Name, "type_cast")
			}
		}

	case *ast.MemberAccess:
		parentName := b.extractParentName(e.Expression)
		switch {
		case parentName == "msg" && e.MemberName == "sender":
			return b.typeInfoFromTypeName("address", "builtin")
		case parentName == "tx" && e.MemberName == "origin":
			return b.typeInfoFromTypeName("address", "builtin")
		case parentName == "msg" && e.MemberName == "value":
			return b.typeInfoFromTypeName("uint256", "builtin")
		}

	case *ast.IndexAccess:
		base := b.expressionType(e.Base)
		if base.ValueType != "" {
			return b.typeInfoFromTypeName(base.ValueType, "mapping_value")
		}
		if base.ElementType != "" {
			return b.typeInfoFromTypeName(base.ElementType, "array_element")
		}
	}

	return types.TypeInfo{}
}

func (cgb *CallGraphBuilder) expressionType(expr ast.Node) types.TypeInfo {
	if expr == nil {
		return types.TypeInfo{}
	}

	switch e := expr.(type) {
	case *ast.Identifier:
		if ti, ok := cgb.symbolTypes[e.Name]; ok {
			return ti
		}
		if e.Name == "this" || e.Name == "super" {
			return cgb.typeInfoFromTypeName(cgb.currentContract, e.Name)
		}
		if isPrimitiveTypeName(e.Name) || cgb.isKnownUserType(e.Name) {
			return cgb.typeInfoFromTypeName(e.Name, "type_identifier")
		}

	case *ast.ElementaryTypeName:
		return cgb.typeInfoFromTypeName(e.Name, "type_identifier")

	case *ast.UserDefinedTypeName:
		return cgb.typeInfoFromTypeName(e.NamePath, "type_identifier")

	case *ast.FunctionCall:
		switch callee := e.Expression.(type) {
		case *ast.ElementaryTypeName:
			return cgb.typeInfoFromTypeName(callee.Name, "type_cast")
		case *ast.UserDefinedTypeName:
			return cgb.typeInfoFromTypeName(callee.NamePath, "type_cast")
		case *ast.Identifier:
			if callee.Name == "payable" {
				return cgb.typeInfoFromTypeName("address payable", "payable_cast")
			}
			if isPrimitiveTypeName(callee.Name) || cgb.isKnownUserType(callee.Name) {
				return cgb.typeInfoFromTypeName(callee.Name, "type_cast")
			}
		}

	case *ast.MemberAccess:
		parentName := extractParentNameFromExpr(e.Expression)
		switch {
		case parentName == "msg" && e.MemberName == "sender":
			return cgb.typeInfoFromTypeName("address", "builtin")
		case parentName == "tx" && e.MemberName == "origin":
			return cgb.typeInfoFromTypeName("address", "builtin")
		case parentName == "msg" && e.MemberName == "value":
			return cgb.typeInfoFromTypeName("uint256", "builtin")
		}

	case *ast.IndexAccess:
		base := cgb.expressionType(e.Base)
		if base.ValueType != "" {
			return cgb.typeInfoFromTypeName(base.ValueType, "mapping_value")
		}
		if base.ElementType != "" {
			return cgb.typeInfoFromTypeName(base.ElementType, "array_element")
		}
	}

	return types.TypeInfo{}
}

func (b *ASTBuilder) typeFromNode(node *types.ASTNode) types.TypeInfo {
	if node == nil {
		return types.TypeInfo{}
	}
	name := node.GetAttributeString("type")
	kind := node.GetAttributeString("type_kind")
	if name == "" || kind == "" {
		return types.TypeInfo{}
	}
	return types.TypeInfo{
		Name:        name,
		BaseName:    node.GetAttributeString("type_base"),
		Kind:        kind,
		ContractID:  node.GetAttributeString("type_contract_id"),
		IsAddress:   node.GetAttributeBool("type_is_address"),
		IsPayable:   node.GetAttributeBool("type_is_payable"),
		Confidence:  node.GetAttributeString("type_confidence"),
		Source:      node.GetAttributeString("type_source"),
		ElementType: node.GetAttributeString("type_element"),
		KeyType:     node.GetAttributeString("type_key"),
		ValueType:   node.GetAttributeString("type_value"),
	}
}

func (b *ASTBuilder) applyTypeAttributes(node *types.ASTNode, ti types.TypeInfo) {
	if node == nil || !ti.IsKnown() {
		return
	}
	node.SetAttribute("type", ti.Name)
	node.SetAttribute("type_base", ti.BaseName)
	node.SetAttribute("type_kind", ti.Kind)
	node.SetAttribute("type_confidence", ti.Confidence)
	node.SetAttribute("type_source", ti.Source)
	if ti.ContractID != "" {
		node.SetAttribute("type_contract_id", ti.ContractID)
	}
	if ti.IsAddress {
		node.SetAttribute("type_is_address", true)
	}
	if ti.IsPayable {
		node.SetAttribute("type_is_payable", true)
	}
	if ti.ElementType != "" {
		node.SetAttribute("type_element", ti.ElementType)
	}
	if ti.KeyType != "" {
		node.SetAttribute("type_key", ti.KeyType)
	}
	if ti.ValueType != "" {
		node.SetAttribute("type_value", ti.ValueType)
	}
}

func (b *ASTBuilder) applyReceiverTypeAttributes(node *types.ASTNode, ti types.TypeInfo) {
	if node == nil || !ti.IsKnown() {
		return
	}
	node.SetAttribute("receiver_type", ti.Name)
	node.SetAttribute("receiver_type_base", ti.BaseName)
	node.SetAttribute("receiver_type_kind", ti.Kind)
	node.SetAttribute("receiver_type_confidence", ti.Confidence)
	if ti.ContractID != "" {
		node.SetAttribute("receiver_type_contract_id", ti.ContractID)
	}
	if ti.IsAddress {
		node.SetAttribute("receiver_type_is_address", true)
	}
	if ti.IsPayable {
		node.SetAttribute("receiver_type_is_payable", true)
	}
}

func (b *ASTBuilder) addSemanticSymbol(name, kind string, ti types.TypeInfo) {
	if b == nil || b.db == nil || b.db.Semantics == nil || name == "" || !ti.IsKnown() {
		return
	}
	refID := b.refIDForSymbol(name, kind)
	if refID == "" {
		return
	}
	var contractID string
	if b.contract != nil {
		contractID = b.contract.ID
	}
	b.db.Semantics.AddSymbol(&types.SemanticSymbol{
		RefID:        refID,
		Name:         name,
		Kind:         kind,
		ContractID:   contractID,
		FunctionID:   b.semanticFunctionID(),
		StorageClass: kind,
		Type:         ti,
	})
}

func (b *ASTBuilder) refIDForSymbol(name, kind string) string {
	if b == nil || b.contract == nil || name == "" {
		return ""
	}
	switch kind {
	case "state_var":
		return fmt.Sprintf("%s#%s.%s", b.contract.SourceFile, b.contract.Name, name)
	case "parameter":
		if b.function == nil {
			return ""
		}
		return fmt.Sprintf("%s#%s.%s.%s", b.contract.SourceFile, b.contract.Name, b.function.Name, name)
	case "local_var":
		if b.function == nil {
			return ""
		}
		return fmt.Sprintf("%s#%s.%s.-%s", b.contract.SourceFile, b.contract.Name, b.function.Name, name)
	default:
		return ""
	}
}

func (b *ASTBuilder) semanticFunctionID() string {
	if b == nil || b.contract == nil || b.function == nil {
		return ""
	}
	fnKey := b.function.Selector
	if fnKey == "" {
		fnKey = b.function.Name
	}
	return types.MakeFunctionID(b.contract.SourceFile, b.contract.Name, fnKey)
}

func (b *ASTBuilder) isKnownUserType(name string) bool {
	if b == nil || b.db == nil || name == "" {
		return false
	}
	return b.db.GetContractByName(baseTypeName(name)) != nil
}

func (cgb *CallGraphBuilder) isKnownUserType(name string) bool {
	if cgb == nil || cgb.db == nil || name == "" {
		return false
	}
	return cgb.db.GetContractByName(baseTypeName(name)) != nil
}

func extractParentNameFromExpr(expr ast.Node) string {
	switch e := expr.(type) {
	case *ast.Identifier:
		return e.Name
	case *ast.MemberAccess:
		return e.MemberName
	default:
		return ""
	}
}

// isAssignmentOperator reports whether a binary operator writes to its LHS.
// Covers plain `=` plus every Solidity compound-assignment operator. Omitting
// the bitwise/shift compounds (`%= &= |= ^= <<= >>=`) previously caused
// state-write detection and taint propagation to silently skip them.
func isAssignmentOperator(op string) bool {
	switch op {
	case "=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=":
		return true
	default:
		return false
	}
}

func baseTypeName(typeName string) string {
	clean := types.CleanTypeName(typeName)
	clean = strings.ReplaceAll(clean, " payable", "")
	if idx := strings.Index(clean, "["); idx > 0 {
		clean = clean[:idx]
	}
	return strings.TrimSpace(clean)
}

func parseArrayElementType(typeName string) string {
	clean := types.CleanTypeName(typeName)
	if idx := strings.Index(clean, "["); idx > 0 && strings.HasSuffix(clean, "]") {
		return strings.TrimSpace(clean[:idx])
	}
	return ""
}

func parseMappingType(typeName string) (keyType, valueType string, ok bool) {
	clean := types.CleanTypeName(typeName)
	if !strings.HasPrefix(clean, "mapping(") || !strings.HasSuffix(clean, ")") {
		return "", "", false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(clean, "mapping("), ")")
	parts := strings.SplitN(inner, "=>", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func isPrimitiveTypeName(typeName string) bool {
	base := baseTypeName(typeName)
	if base == "address" || base == "bool" || base == "string" || base == "bytes" {
		return true
	}
	if base == "byte" {
		return true
	}
	if strings.HasPrefix(base, "uint") || strings.HasPrefix(base, "int") {
		return true
	}
	if strings.HasPrefix(base, "bytes") {
		return true
	}
	return false
}
