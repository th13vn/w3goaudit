package main

// extract_involve.go — `extract involve <function>`.
//
// Returns every workflow that "involves" the named function: for each
// entry point of the project, if the call graph reaches the target
// function from that entry, emit a Mermaid flowchart of the path(s).
//
// This subcommand replaces the older `extract callgraph` (with its
// --reverse / --mermaid flags). Auditors don't want a flat edge list;
// they want "show me which entry points are at risk because they
// transitively call _transfer". `involve` is that question.
//
// Output is markdown by default — each entry-point workflow is its own
// `## entrypoint Contract.func` section with a fenced ```mermaid block.
// `--format=json` emits a structured list of workflows + edges.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// InvolveOutput is the JSON shape of `extract involve`. Each workflow
// describes one entry point and the path that reaches the target function.
type InvolveOutput struct {
	SchemaVersion string            `json:"schemaVersion"`
	Function      string            `json:"function"`
	Targets       []string          `json:"targets,omitempty"` // all matched targets when name is ambiguous
	Workflows     []InvolveWorkflow `json:"workflows"`
}

// InvolveWorkflow is one entry-point's path to the target.
type InvolveWorkflow struct {
	EntryFunction string         `json:"entryFunction"` // "Contract.func"
	EntryFuncID   string         `json:"entryFuncId"`   // fully-qualified ID
	Edges         []CallEdgeInfo `json:"edges"`         // every edge walked on the reachable subtree
	Mermaid       string         `json:"mermaid"`       // ready-to-render flowchart
}

var extractInvolveCmd = &cobra.Command{
	Use:   "involve <function-name> [path]",
	Short: "Show every entry-point workflow that involves a function (as Mermaid charts)",
	Long: `For each entry-point function in the project, walk the call graph from
that entry. If the target function is reachable, emit a Mermaid flowchart
of the path. Useful for "which user-facing functions are affected if I
audit this helper?".

Examples:
  w3goaudit extract involve _transfer ./contracts/
  w3goaudit extract involve _transfer --db database.json
  w3goaudit extract involve _checkOwner --db database.json -o involve.md
  w3goaudit extract involve withdraw --db database.json --format=json`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		outPath, _ := cmd.Flags().GetString("output")

		db, err := resolveExtractDB(cmd, args)
		if err != nil {
			return err
		}
		fn, contract, err := resolveFunctionQuery(db, args[0], "")
		if err != nil {
			return err
		}
		funcName := fn.Name
		targets := []string{exactFunctionID(contract, fn)}
		targetSet := make(map[string]bool, len(targets))
		for _, t := range targets {
			targetSet[t] = true
		}

		// Walk every entry function of every main contract. If it transitively
		// reaches the target, capture the workflow.
		var workflows []InvolveWorkflow
		entryIDs := collectEntryFuncIDs(db)
		for _, entryID := range entryIDs {
			edges, reaches := reachableEdgesToTargets(db, entryID, targetSet, 32)
			if !reaches {
				continue
			}
			edgeInfos := make([]CallEdgeInfo, 0, len(edges))
			for _, e := range edges {
				edgeInfos = append(edgeInfos, CallEdgeInfo{
					From: e.From, To: e.To,
					Type: string(e.Type), Line: e.Line, Resolved: e.Resolved,
				})
			}
			workflows = append(workflows, InvolveWorkflow{
				EntryFunction: shortFuncName(entryID),
				EntryFuncID:   entryID,
				Edges:         edgeInfos,
				Mermaid:       buildInvolveMermaid(entryID, edges, targetSet),
			})
		}

		// Stable order for diff-friendly output.
		sort.SliceStable(workflows, func(i, j int) bool {
			return workflows[i].EntryFunction < workflows[j].EntryFunction
		})

		output := InvolveOutput{
			SchemaVersion: ExtractSchemaVersion,
			Function:      funcName,
			Targets:       targets,
			Workflows:     workflows,
		}

		return writeExtract(output,
			func() string { return renderInvolveMarkdown(output) },
			outPath, resolveExtractFormat(cmd))
	},
}

func init() {
	extractInvolveCmd.Flags().String("db", "", "Path to a pre-built database JSON (optional; or pass a source path)")
	extractInvolveCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
	addExtractFormatFlag(extractInvolveCmd)
}

// collectEntryFuncIDs returns every entry-point function ID in the database,
// sorted by Contract.func name for stable output ordering.
func collectEntryFuncIDs(db *types.Database) []string {
	var out []string
	for _, entry := range db.MainContracts {
		out = append(out, entry.EntryFunctions...)
	}
	sort.Slice(out, func(i, j int) bool {
		return shortFuncName(out[i]) < shortFuncName(out[j])
	})
	return out
}

// reachableEdgesToTargets walks the call graph from entryID and returns
// every edge on a path that lands at any function in targets. The second
// return is true iff at least one such path exists.
//
// Uses a two-pass approach: BFS to find all reachable nodes, then prune to
// edges that lie on a path to a target. This is cheap on real projects
// (call-graph fan-out is small) and gives us the minimal subgraph for the
// Mermaid chart instead of dumping the whole reachable cone.
func reachableEdgesToTargets(
	db *types.Database, entryID string,
	targets map[string]bool, maxDepth int,
) ([]*types.CallEdge, bool) {
	if db.CallGraph == nil {
		return nil, false
	}

	// Phase 1 — BFS forward from entry, record edges in order seen.
	type queueItem struct {
		id    string
		depth int
	}
	visited := make(map[string]bool)
	parents := make(map[string][]*types.CallEdge) // edge.To → incoming edges
	queue := []queueItem{{entryID, 0}}
	visited[entryID] = true
	reachesTarget := false

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		if targets[item.id] {
			reachesTarget = true
		}
		if item.depth >= maxDepth {
			continue
		}
		for _, edge := range db.CallGraph.GetCallees(item.id) {
			parents[edge.To] = append(parents[edge.To], edge)
			if !visited[edge.To] {
				visited[edge.To] = true
				queue = append(queue, queueItem{edge.To, item.depth + 1})
			}
		}
	}

	if !reachesTarget {
		return nil, false
	}

	// Phase 2 — back-walk from every target node, collecting edges that
	// landed on it (and recursively their predecessors). The edges we keep
	// are exactly the ones on some entry→target path.
	keep := make(map[*types.CallEdge]bool)
	frontier := make([]string, 0, len(targets))
	for t := range targets {
		if visited[t] {
			frontier = append(frontier, t)
		}
	}
	seen := make(map[string]bool)
	for len(frontier) > 0 {
		node := frontier[0]
		frontier = frontier[1:]
		if seen[node] {
			continue
		}
		seen[node] = true
		for _, e := range parents[node] {
			if keep[e] {
				continue
			}
			keep[e] = true
			frontier = append(frontier, e.From)
		}
	}

	// Stable order: by (From, To, Line) so reruns produce identical output.
	out := make([]*types.CallEdge, 0, len(keep))
	for e := range keep {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].To != out[j].To {
			return out[i].To < out[j].To
		}
		return out[i].Line < out[j].Line
	})
	return out, true
}

// buildInvolveMermaid renders the entry→target subgraph as a Mermaid
// flowchart. The entry node is highlighted; target nodes are highlighted.
// Edges are labeled with the call type when non-empty.
func buildInvolveMermaid(entryID string, edges []*types.CallEdge, targets map[string]bool) string {
	if len(edges) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("graph LR\n")
	// Track which nodes we've declared so we can apply highlight styles once.
	declared := make(map[string]bool)
	emit := func(id string) string {
		nodeID := safeMermaidID(id)
		if !declared[id] {
			fmt.Fprintf(&sb, "    %s[\"%s\"]\n", nodeID, shortFuncName(id))
			declared[id] = true
		}
		return nodeID
	}
	for _, e := range edges {
		from := emit(e.From)
		to := emit(e.To)
		if e.Type != "" {
			fmt.Fprintf(&sb, "    %s -->|%s| %s\n", from, e.Type, to)
		} else {
			fmt.Fprintf(&sb, "    %s --> %s\n", from, to)
		}
	}
	// Highlight styling: entry = orange, target = red.
	fmt.Fprintf(&sb, "    style %s fill:#ff9f43,color:#fff\n", safeMermaidID(entryID))
	for t := range targets {
		if declared[t] {
			fmt.Fprintf(&sb, "    style %s fill:#e55353,color:#fff\n", safeMermaidID(t))
		}
	}
	return sb.String()
}

// safeMermaidID sanitizes a function ID for use as a Mermaid node identifier.
// Mermaid IDs can't contain quotes, dots, or hashes; we replace them with
// underscores. Two different IDs produce two different Mermaid IDs as long
// as the underlying string is distinct (no hashing — preserves readability
// for short test fixtures, and the underscore-encoded form is still unique).
func safeMermaidID(id string) string {
	r := strings.NewReplacer(
		"#", "_",
		".", "_",
		"/", "_",
		" ", "_",
		"(", "_",
		")", "_",
		",", "_",
		":", "_",
		"-", "_",
	)
	return "n_" + r.Replace(id)
}

// renderInvolveMarkdown renders the involve output as a markdown document:
// one section per workflow, each with its Mermaid chart.
func renderInvolveMarkdown(o InvolveOutput) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Involve: `%s`\n\n", o.Function)
	fmt.Fprintf(&sb, "**Workflows reaching this function:** %d\n\n", len(o.Workflows))
	if len(o.Targets) > 1 {
		sb.WriteString("**Matched targets (function name was ambiguous):**\n\n")
		for _, t := range o.Targets {
			fmt.Fprintf(&sb, "- `%s`\n", t)
		}
		sb.WriteString("\n")
	}
	if len(o.Workflows) == 0 {
		sb.WriteString("_(no entry-point workflows reach this function)_\n")
		return sb.String()
	}
	for _, wf := range o.Workflows {
		fmt.Fprintf(&sb, "## entrypoint `%s`\n\n", wf.EntryFunction)
		if wf.Mermaid != "" {
			sb.WriteString("```mermaid\n")
			sb.WriteString(wf.Mermaid)
			sb.WriteString("```\n\n")
		} else {
			sb.WriteString("_(direct call; no intermediate edges)_\n\n")
		}
	}
	return sb.String()
}
