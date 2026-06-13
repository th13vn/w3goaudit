package report

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// ToMarkdown converts the summary report to Markdown format
func (r *SummaryReport) ToMarkdown() string {
	var sb strings.Builder

	// Header
	sb.WriteString("# Project Summary Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n", r.GeneratedAt.Format("2006-01-02 15:04:05")))
	if r.GitInfo != nil && r.GitInfo.RemoteURL != "" {
		sb.WriteString(fmt.Sprintf("**Repository:** [%s](%s)  \n", r.GitInfo.RemoteURL, r.GitInfo.RemoteURL))
		sb.WriteString(fmt.Sprintf("**Branch:** `%s`  \n", r.GitInfo.Branch))
	} else if r.ProjectRoot != "" {
		sb.WriteString(fmt.Sprintf("**Project Root:** `%s`  \n", r.ProjectRoot))
	}
	if r.Stats.Framework != "" && r.Stats.Framework != "unknown" {
		sb.WriteString(fmt.Sprintf("**Framework:** `%s`  \n", r.Stats.Framework))
	}
	sb.WriteString("\n")

	// Project Metrics
	if r.Stats != nil {
		sb.WriteString("## Project Metrics\n\n")
		sb.WriteString("| Metric | Value |\n")
		sb.WriteString("|--------|-------|\n")
		sb.WriteString(fmt.Sprintf("| Source Files | %d |\n", r.Stats.TotalFiles))
		sb.WriteString(fmt.Sprintf("| nSLOC | %d |\n", r.Stats.NSLOC))
		sb.WriteString(fmt.Sprintf("| Total Contracts | %d |\n", r.Stats.TotalContracts+r.Stats.TotalInterfaces+r.Stats.TotalLibraries))
		sb.WriteString(fmt.Sprintf("| - Contracts | %d |\n", r.Stats.TotalContracts))
		sb.WriteString(fmt.Sprintf("| - Interfaces | %d |\n", r.Stats.TotalInterfaces))
		sb.WriteString(fmt.Sprintf("| - Libraries | %d |\n", r.Stats.TotalLibraries))
		sb.WriteString(fmt.Sprintf("| Total Functions | %d |\n", r.Stats.TotalFunctions))
		sb.WriteString(fmt.Sprintf("| Entry Functions | %d |\n", r.Stats.TotalEntryFunctions))
		sb.WriteString(fmt.Sprintf("| Main Contracts | %d |\n", len(r.MainContracts)))
		sb.WriteString("\n---\n\n")
	}

	// Main Contracts
	for _, contract := range r.MainContracts {
		sb.WriteString(contract.toMarkdownWithGit(r.GitInfo, r.ProjectRoot))
		sb.WriteString("\n---\n\n")
	}

	return sb.String()
}

// toMarkdownWithGit converts a contract summary to Markdown format with git URL support
func (c *ContractSummary) toMarkdownWithGit(gitInfo *GitInfo, projectRoot string) string {
	var sb strings.Builder

	// Contract header
	sb.WriteString(fmt.Sprintf("## %s\n\n", c.Name))

	// File path - use git URL if available
	fileDisplay := c.SourceFile
	if gitInfo != nil && gitInfo.RemoteURL != "" && projectRoot != "" {
		if relPath, err := filepath.Rel(projectRoot, c.SourceFile); err == nil {
			relPath = strings.ReplaceAll(relPath, "\\", "/")
			gitURL := gitInfo.RemoteURL + "/blob/" + gitInfo.Branch + "/" + relPath
			fileDisplay = fmt.Sprintf("[%s](%s)", relPath, gitURL)
		}
	}
	sb.WriteString(fmt.Sprintf("**File:** %s  \n", fileDisplay))
	sb.WriteString(fmt.Sprintf("**Entry Points:** %d  \n", c.EntryFunctionCount))
	sb.WriteString(fmt.Sprintf("**State Variables:** %d  \n", c.StateVariableCount))
	sb.WriteString("\n")

	// Rest of the contract rendering (append from line 60 onwards)
	sb.WriteString(c.renderRestOfContract())

	return sb.String()
}

// ToMarkdown converts a contract summary to Markdown format (backward compatible)
func (c *ContractSummary) ToMarkdown() string {
	return c.toMarkdownWithGit(nil, "")
}

// renderRestOfContract renders the rest of contract (inheritance, functions, etc)
func (c *ContractSummary) renderRestOfContract() string {
	var sb strings.Builder

	// Inheritance Graph — render three views (Tree → Flattened → Mermaid) so
	// reviewers can pick the level of detail that matches the question they
	// have. The flattened line is especially useful when feeding the overview
	// into an LLM: one short line conveys the full MRO without re-reading the
	// tree drawing.
	if c.InheritanceMermaid != "" && strings.Contains(c.InheritanceMermaid, "-->") {
		sb.WriteString("### Inheritance\n\n")
		// 1. ASCII tree (parent → child hierarchy, visual).
		sb.WriteString("```\n")
		sb.WriteString(c.renderInheritanceTree())
		sb.WriteString("```\n\n")
		// 2. Flattened linearization (single line, most-child → most-parent).
		//    This is the C3 MRO direction auditors actually reason in.
		sb.WriteString("**Flattened (derived → base):** ")
		sb.WriteString(c.renderInheritanceFlattened())
		sb.WriteString("\n\n")
		// 3. Mermaid diagram (interactive form for HTML report).
		sb.WriteString("```mermaid\n")
		sb.WriteString(c.InheritanceMermaid)
		sb.WriteString("```\n\n")
	} else if len(c.InheritanceChain) > 1 {
		// Fallback when no inheritance edges are recorded (e.g. single base).
		sb.WriteString("### Inheritance Chain\n\n")
		sb.WriteString("**Flattened (derived → base):** ")
		sb.WriteString(c.renderInheritanceFlattened())
		sb.WriteString("\n\n")
		sb.WriteString("| Order | Contract | Kind |\n")
		sb.WriteString("|-------|----------|------|\n")
		for _, inherited := range c.InheritanceChain {
			sb.WriteString(fmt.Sprintf("| %d | %s | %s |\n",
				inherited.Order, inherited.Name, inherited.Kind))
		}
		sb.WriteString("\n")
	}

	// Entry Functions - grouped by Access Control and Defined In
	if len(c.EntryFunctions) > 0 {
		sb.WriteString("### Entry Functions\n\n")

		// Map: AccessControlled (bool) -> DefinedIn (string) -> Functions
		grouped := make(map[bool]map[string][]*FunctionSummary)
		// Initialize maps
		grouped[true] = make(map[string][]*FunctionSummary)
		grouped[false] = make(map[string][]*FunctionSummary)

		for _, fn := range c.EntryFunctions {
			definedIn := fn.DefinedIn
			if definedIn == c.Name {
				definedIn = "_self_" // Use special key for sorting
			}
			grouped[fn.IsAccessControlled][definedIn] = append(grouped[fn.IsAccessControlled][definedIn], fn)
		}

		// Helper to render a group
		renderGroup := func(isAccessControlled bool, label string) {
			groups := grouped[isAccessControlled]
			if len(groups) == 0 {
				return
			}

			sb.WriteString(fmt.Sprintf("#### %s\n\n", label))

			// Iterate contracts
			// 1. Check self
			if fns, ok := groups["_self_"]; ok {
				sb.WriteString("##### Defined in *self*\n\n")
				for _, fn := range fns {
					c.renderEntryFunction(&sb, fn)
				}
			}

			// 2. Others — sorted for deterministic output.
			others := make([]string, 0, len(groups))
			for k := range groups {
				if k != "_self_" {
					others = append(others, k)
				}
			}
			sort.Strings(others)
			for _, k := range others {
				sb.WriteString(fmt.Sprintf("##### Defined in *%s*\n\n", k))
				for _, fn := range groups[k] {
					c.renderEntryFunction(&sb, fn)
				}
			}
		}

		renderGroup(true, "🔒 Access Controlled")
		renderGroup(false, "🔓 Unprotected")
	}

	// View Functions
	if len(c.ViewFunctions) > 0 {
		sb.WriteString("### View Functions\n\n")
		sb.WriteString("<details>\n<summary>Show view functions</summary>\n\n")
		sb.WriteString("| Name | Signature | Defined In |\n")
		sb.WriteString("|------|-----------|------------|\n")
		for _, fn := range c.ViewFunctions {
			definedIn := fn.DefinedIn
			if definedIn == c.Name {
				definedIn = "*self*"
			}
			sig := fn.Signature
			if sig == "" {
				sig = fn.Name
			}
			name := fn.Selector
			if name == "" {
				name = fn.Name
			}
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %s |\n", name, sig, definedIn))
		}
		sb.WriteString("\n</details>\n\n")
	}

	// Internal Functions
	if len(c.InternalFunctions) > 0 {
		sb.WriteString("### Internal Functions\n\n")
		sb.WriteString("<details>\n<summary>Show internal functions</summary>\n\n")
		sb.WriteString("| Name | Signature | Defined In |\n")
		sb.WriteString("|------|-----------|------------|\n")
		for _, fn := range c.InternalFunctions {
			definedIn := fn.DefinedIn
			if definedIn == c.Name {
				definedIn = "*self*"
			}
			sig := fn.Signature
			if sig == "" {
				sig = fn.Name
			}
			name := fn.Selector
			if name == "" {
				name = fn.Name
			}
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %s |\n", name, sig, definedIn))
		}
		sb.WriteString("\n</details>\n\n")
	}

	// State Variables
	if len(c.StateVariables) > 0 {
		sb.WriteString("### State Variables\n\n")
		sb.WriteString("<details>\n<summary>Show state variables</summary>\n\n")
		sb.WriteString("| Name | Type | Defined In |\n")
		sb.WriteString("|------|------|------------|\n")
		for _, sv := range c.StateVariables {
			definedIn := sv.DefinedIn
			if definedIn == c.Name {
				definedIn = "*self*"
			}
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %s |\n", sv.Name, sv.TypeName, definedIn))
		}
		sb.WriteString("\n</details>\n")
	}

	return sb.String()
}

// renderInheritanceFlattened renders the C3 linearization as a single line
// in derived → base order, e.g. `MyToken → ERC20 → Ownable → Context`.
//
// The InheritanceChain field is already stored derived-first by the
// generator (most-derived contract at index 0), so we just join the
// contract names with " → ". Returns "—" when there's no chain to render
// so the surrounding markdown stays well-formed.
func (c *ContractSummary) renderInheritanceFlattened() string {
	if len(c.InheritanceChain) == 0 {
		return "—"
	}
	names := make([]string, 0, len(c.InheritanceChain))
	for _, inh := range c.InheritanceChain {
		names = append(names, "`"+inh.Name+"`")
	}
	return strings.Join(names, " → ")
}

// renderInheritanceTree renders the inheritance hierarchy as an ASCII tree
func (c *ContractSummary) renderInheritanceTree() string {
	// Parse Mermaid graph to extract edges: child --> parent
	// Format: n12345["ChildName"] --> n67890["ParentName"]
	childToParents := make(map[string][]string)
	parentToChildren := make(map[string][]string)
	allNodes := make(map[string]bool)

	lines := strings.Split(c.InheritanceMermaid, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "-->") {
			continue
		}

		// Extract node names from quoted labels
		parts := strings.Split(line, "-->")
		if len(parts) != 2 {
			continue
		}

		childName := extractNodeLabel(parts[0])
		parentName := extractNodeLabel(parts[1])

		if childName == "" || parentName == "" {
			continue
		}

		allNodes[childName] = true
		allNodes[parentName] = true
		childToParents[childName] = append(childToParents[childName], parentName)
		parentToChildren[parentName] = append(parentToChildren[parentName], childName)
	}

	// The main contract is first in inheritance chain
	if len(c.InheritanceChain) == 0 {
		return ""
	}
	root := c.InheritanceChain[0].Name

	// Build tree recursively
	var sb strings.Builder
	sb.WriteString(root)
	sb.WriteString("\n")
	renderTreeBranch(&sb, root, childToParents, "", true)

	return sb.String()
}

// extractNodeLabel extracts the label from a Mermaid node like: n12345["ContractName"]
func extractNodeLabel(s string) string {
	s = strings.TrimSpace(s)
	startQuote := strings.Index(s, `["`)
	endQuote := strings.Index(s, `"]`)
	if startQuote != -1 && endQuote != -1 && endQuote > startQuote+2 {
		return s[startQuote+2 : endQuote]
	}
	return ""
}

// renderTreeBranch renders children of a node recursively
func renderTreeBranch(sb *strings.Builder, node string, childToParents map[string][]string, prefix string, isLast bool) {
	// Find direct parents of this node (in the Mermaid graph, child --> parent means node inherits from parent)
	parents := childToParents[node]
	for i, parent := range parents {
		isLastParent := i == len(parents)-1

		// Choose connector
		connector := "├── "
		if isLastParent {
			connector = "└── "
		}

		sb.WriteString(prefix)
		sb.WriteString(connector)
		sb.WriteString(parent)
		sb.WriteString("\n")

		// Calculate new prefix for children
		newPrefix := prefix
		if isLastParent {
			newPrefix += "    "
		} else {
			newPrefix += "│   "
		}

		// Recurse into parent's parents
		renderTreeBranch(sb, parent, childToParents, newPrefix, isLastParent)
	}
}

// renderEntryFunction renders a single entry function in Markdown
func (c *ContractSummary) renderEntryFunction(sb *strings.Builder, fn *FunctionSummary) {
	payable := ""
	if fn.IsPayable {
		payable = " 💰"
	}
	selector := fn.Selector
	if selector == "" {
		selector = fn.Name
	}
	sig := fn.Signature
	if sig == "" {
		sig = "-"
	}

	// Construct string for modifiers
	modStr := ""
	if len(fn.Modifiers) > 0 {
		modStr = fmt.Sprintf(" (%s)", strings.Join(fn.Modifiers, ", "))
	}

	// Simplified format: name - signature (modifier list)
	// <summary>renounceOwnership() - <code>715018a6</code> (onlyOwner)</summary>
	sb.WriteString(fmt.Sprintf("<details>\n<summary>%s - <code>%s</code>%s%s</summary>\n\n",
		selector, sig, payable, modStr))

	// Add the function's call graph if it has edges
	if fn.CallGraphMermaid != "" && strings.Contains(fn.CallGraphMermaid, "-->") {
		sb.WriteString("```mermaid\n")
		sb.WriteString(fn.CallGraphMermaid)
		sb.WriteString("```\n")
	} else {
		sb.WriteString("*No internal calls*\n")
	}
	sb.WriteString("\n</details>\n\n")
}
