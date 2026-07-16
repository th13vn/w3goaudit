package report

import (
	"fmt"
	"html"
	"path/filepath"
	"sort"
	"strings"
)

// ToHTML converts the summary report to a standalone HTML file
func (r *SummaryReport) ToHTML() string {
	var sb strings.Builder

	// HTML Header with CSS and Scripts
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>W3GoAudit Report</title>
    <!-- vis-network (v9.1.9) is embedded inline (see pkg/report/assets.go) so
         the report is fully offline: no CDN request, no supply-chain exposure. -->
    <script type="text/javascript">` + visNetworkJS + `</script>
    <style>
        :root {
            --bg-color: #1a1b26;
            --text-color: #a9b1d6;
            --heading-color: #7aa2f7;
            --card-bg: #24283b;
            --border-color: #414868;
            --accent-color: #bb9af7;
            --code-bg: #292e42;
            --graph-node-bg: #24283b;
            --graph-node-border: #7aa2f7;
            --graph-edge-color: #565f89;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        h1, h2, h3 {
            color: var(--heading-color);
        }
        .header {
            margin-bottom: 30px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
        }
        .card {
            background-color: var(--card-bg);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .metric-card {
            background-color: var(--code-bg);
            padding: 15px;
            border-radius: 6px;
            text-align: center;
        }
        .metric-card .value {
            font-size: 24px;
            font-weight: bold;
            color: var(--accent-color);
        }
        .metric-card .label {
            font-size: 14px;
            opacity: 0.8;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            text-align: left;
            padding: 10px;
            border-bottom: 1px solid var(--border-color);
        }
        th {
            color: var(--heading-color);
        }
        code {
            background-color: var(--code-bg);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9em;
        }
        details {
            margin: 10px 0;
            cursor: pointer;
            border-left: 2px solid var(--border-color);
            padding-left: 10px;
        }
        summary {
            color: var(--accent-color);
            font-weight: bold;
            padding: 5px 0;
        }
        
        /* Interactive Graph Styles */
        .network-container {
            height: 400px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background-color: var(--bg-color);
            margin-bottom: 10px;
            position: relative;
        }
        
        /* Full Screen Overlay */
        #fullscreen-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background-color: var(--bg-color);
            z-index: 9999;
            padding: 20px;
            box-sizing: border-box;
        }
        
        #fullscreen-graph {
            width: 100%;
            height: 90%;
            border: 1px solid var(--border-color);
        }
        
        .fullscreen-controls {
            height: 10%;
            display: flex;
            justify-content: flex-end;
            align-items: center;
        }
        
        .btn {
            background-color: var(--accent-color);
            color: #fff;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .btn:hover {
            opacity: 0.9;
        }
        
        .fs-btn {
            position: absolute;
            top: 10px;
            right: 10px;
            z-index: 10;
        }
    </style>
    <script>
        // Graph Initialization Logic
        window.initGraphs = function() {
            document.querySelectorAll('.network-container').forEach(container => {
                // Skip if already initialized (unless we force it)
                if (container.dataset.initialized) return;
                
                const rawCode = container.getAttribute('data-raw');
                if (!rawCode) return;
                
                renderGraph(container, rawCode);
                container.dataset.initialized = "true";
                
                // Add fullscreen button
                const btn = document.createElement('button');
                btn.className = 'btn fs-btn';
                btn.innerText = '⛶ Full Screen';
                btn.onclick = (e) => {
                    e.stopPropagation(); // Prevent detail toggle
                    openFullScreen(rawCode);
                };
                container.appendChild(btn);
            });
        }
        
        function renderGraph(container, rawData) {
            const data = parseMermaidData(rawData);
            
            // Vis.js Configuration
            const options = {
                nodes: {
                    shape: 'box',
                    font: {
                        color: '#ffffff',
                        face: 'Segoe UI'
                    },
                    color: {
                        background: '#24283b',
                        border: '#7aa2f7',
                        highlight: {
                            background: '#3b4261',
                            border: '#bb9af7'
                        },
                        hover: {
                            background: '#3b4261',
                            border: '#bb9af7'
                        }
                    },
                    margin: 10,
                    borderWidth: 1,
                    shadow: true 
                },
                edges: {
                    arrows: 'to',
                    color: {
                        color: '#565f89',
                        highlight: '#bb9af7',
                        hover: '#bb9af7'
                    },
                    smooth: {
                        type: 'cubicBezier',
                        roundness: 0.4
                    }
                },
                layout: {
                    hierarchical: {
                        enabled: true,
                        direction: 'LR',
                        sortMethod: 'directed',
                        nodeSpacing: 100,
                        levelSeparation: 250
                    }
                },
                physics: {
                    enabled: false
                },
                interaction: {
                    hover: true,
                    dragNodes: true,
                    zoomView: false,
                    dragView: true
                }
            };
            
            // Create Network
            const network = new vis.Network(container, data, options);

            // Interaction Logic: Enable zoom only on click/focus
            container.addEventListener('click', () => {
                 network.setOptions({ interaction: { zoomView: true } });
            });

            container.addEventListener('mouseleave', () => {
                 network.setOptions({ interaction: { zoomView: false } });
            });
            
            return network;
        }

        function parseMermaidData(chart) {
           const lines = chart.split('\n');
           const nodes = new vis.DataSet([]);
           const edges = new vis.DataSet([]);
           const nodeMap = new Map();

           // Parsing Mermaid Logic for Vis.js
           
           // First pass: nodes
           // Pattern: id["label"]
           // Use global match to find all definitions on a line (e.g. A["L1"] --> B["L2"])
           const nodeRegex = /([a-zA-Z0-9_]+)\["([^"]+)"\]/g;
           lines.forEach(line => {
                const matches = [...line.matchAll(nodeRegex)];
                matches.forEach(match => {
                    const id = match[1];
                    const label = match[2];
                    if (!nodeMap.has(id)) {
                        nodeMap.set(id, { id: id, label: label });
                        nodes.add({ id: id, label: label });
                    }
                });
           });
           
           // Second pass: edges
           lines.forEach(line => {
               if (line.includes('-->')) {
                   const parts = line.split('-->');
                   const fromId = extractId(parts[0]);
                   const toRaw = parts[1].trim();
                   
                   let toId = "";
                   let label = "";
                   
                   // Check for label |label|
                   if (toRaw.startsWith('|')) {
                       const labelEnd = toRaw.indexOf('|', 1);
                       if (labelEnd > 1) {
                           label = toRaw.substring(1, labelEnd);
                           toId = extractId(toRaw.substring(labelEnd + 1));
                       } else {
                           toId = extractId(toRaw);
                       }
                   } else {
                       toId = extractId(toRaw);
                   }
                   
                   if (fromId && toId) {
                      // Ensure nodes exist (if defined without label in edges)
                      if (!nodeMap.has(fromId)) {
                           nodes.add({ id: fromId, label: fromId });
                           nodeMap.set(fromId, true);
                      }
                      if (!nodeMap.has(toId)) {
                           nodes.add({ id: toId, label: toId });
                           nodeMap.set(toId, true);
                      }
                      
                      edges.add({ from: fromId, to: toId, label: label, font: {align: 'middle'} });
                   }
               }
           });
           
           // Color overrides from mermaid 'style'
           // style nXXX fill:#...,color:#...
           const styleRegex = /style\s+([a-zA-Z0-9_]+)\s+fill:([^,]+),color:([^,\s]+)/;
           lines.forEach(line => {
               const match = line.match(styleRegex);
               if (match) {
                   const id = match[1];
                   const bg = match[2];
                   
                   try {
                       nodes.update({ 
                           id: id, 
                           color: { 
                               background: bg, 
                               border: bg 
                           } 
                       });
                   } catch (e) {}
               }
           });

            return { nodes, edges };
        }

        function extractId(str) {
            const match = str.trim().match(/^([a-zA-Z0-9_]+)/);
            return match ? match[1] : null;
        }
        
        // Full Screen Logic
        function openFullScreen(rawData) {
            const overlay = document.getElementById('fullscreen-overlay');
            const graphContainer = document.getElementById('fullscreen-graph');
            
            overlay.style.display = 'block';
            
            // Simple render, but enable zoom by default
            const net = renderGraph(graphContainer, rawData);
            net.setOptions({ interaction: { zoomView: true } });
        }
        
        function closeFullScreen() {
             document.getElementById('fullscreen-overlay').style.display = 'none';
        }

        // Initialize on load
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initGraphs);
        } else {
            initGraphs();
        }
    </script>
</head>
<body>
    <div id="fullscreen-overlay">
        <div class="fullscreen-controls">
            <button class="btn" onclick="closeFullScreen()">Close</button>
        </div>
        <div id="fullscreen-graph"></div>
    </div>

    <div class="container">
        <div class="header" style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1>Project Summary Report</h1>
                <p>Generated: ` + r.GeneratedAt.Format("2006-01-02 15:04:05") + `</p>
                ` + r.renderGitInfoHTML() + `
            </div>
            <button class="btn" onclick="window.print()">Export to PDF</button>
        </div>

        <!-- Metrics -->
        <!-- Metrics -->
        <div class="metric-grid">
			 <div class="metric-card">
                 <div class="value">` + r.Stats.Framework + `</div>
                 <div class="label">Framework</div>
            </div>
            <div class="metric-card">
                 <div class="value">` + fmt.Sprintf("%d", r.Stats.TotalFiles) + `</div>
                 <div class="label">Files</div>
            </div>
             <div class="metric-card">
                 <div class="value">` + fmt.Sprintf("%d", r.Stats.NSLOC) + `</div>
                 <div class="label">nSLOC</div>
            </div>
            <div class="metric-card">
                 <div class="value">` + fmt.Sprintf("%d", r.Stats.TotalContracts+r.Stats.TotalInterfaces+r.Stats.TotalLibraries) + `</div>
                 <div class="label">Total Contracts</div>
            </div>
             <div class="metric-card">
                 <div class="value">` + fmt.Sprintf("%d", r.Stats.TotalFunctions) + `</div>
                 <div class="label">Functions</div>
            </div>
             <div class="metric-card">
                 <div class="value">` + fmt.Sprintf("%d", r.Stats.TotalEntryFunctions) + `</div>
                 <div class="label">Entry Functions</div>
            </div>
        </div>

        <!-- Contracts -->
        ` + r.renderContractsHTML() + `
    </div>
</body>
</html>
`)
	return sb.String()
}

// renderGitInfoHTML renders git repository info or falls back to project root.
// All interpolations are HTML-escaped — the same hardening applied to the
// findings renderer (scan_formats.go) must hold here, since type strings,
// signatures, and paths surfaced in the overview are not identifier-constrained.
func (r *SummaryReport) renderGitInfoHTML() string {
	if r.GitInfo != nil && r.GitInfo.RemoteURL != "" {
		u := html.EscapeString(r.GitInfo.RemoteURL)
		return fmt.Sprintf(`<p>Repository: <a href="%s" target="_blank">%s</a> (branch: <code>%s</code>)</p>`,
			u, u, html.EscapeString(r.GitInfo.Branch))
	}
	return fmt.Sprintf(`<p>Project Root: <code>%s</code></p>`, html.EscapeString(r.ProjectRoot))
}

func (r *SummaryReport) renderContractsHTML() string {
	var sb strings.Builder
	for _, c := range r.MainContracts {
		sb.WriteString(c.toHTMLWithGit(r.GitInfo, r.ProjectRoot))
	}
	return sb.String()
}

// toHTMLWithGit converts a contract summary to HTML with git URL support
func (c *ContractSummary) toHTMLWithGit(gitInfo *GitInfo, projectRoot string) string {
	var sb strings.Builder

	sb.WriteString(`<div class="card">`)
	sb.WriteString(fmt.Sprintf("<h2>%s</h2>", html.EscapeString(c.Name)))

	// File path - use git URL if available
	fileDisplay := fmt.Sprintf("<code>%s</code>", html.EscapeString(c.SourceFile))
	if gitInfo != nil && gitInfo.RemoteURL != "" && projectRoot != "" {
		if relPath, err := filepath.Rel(projectRoot, c.SourceFile); err == nil {
			relPath = strings.ReplaceAll(relPath, "\\", "/")
			gitURL := gitInfo.RemoteURL + "/blob/" + gitInfo.Branch + "/" + relPath
			fileDisplay = fmt.Sprintf(`<a href="%s" target="_blank">%s</a>`, html.EscapeString(gitURL), html.EscapeString(relPath))
		}
	}
	sb.WriteString(fmt.Sprintf("<p><strong>File:</strong> %s</p>", fileDisplay))
	sb.WriteString(fmt.Sprintf("<p><strong>Entry Points:</strong> %d</p>", c.EntryFunctionCount))
	sb.WriteString(fmt.Sprintf("<p><strong>State Variables:</strong> %d</p>", c.StateVariableCount))

	// Render rest of the contract (inheritance, functions, etc)
	sb.WriteString(c.renderRestOfHTML())

	return sb.String()
}

// ToHTML converts a contract summary to HTML (backward compatible)
func (c *ContractSummary) ToHTML() string {
	return c.toHTMLWithGit(nil, "")
}

// renderRestOfHTML renders the rest of the contract HTML (inheritance, functions, etc)
func (c *ContractSummary) renderRestOfHTML() string {
	var sb strings.Builder

	// Inheritance — Tree → Flattened (single line, derived → base) → Mermaid.
	// Same three-view structure as the markdown renderer so the HTML and MD
	// outputs stay in lockstep.
	if c.InheritanceMermaid != "" && strings.Contains(c.InheritanceMermaid, "-->") {
		sb.WriteString("<h3>Inheritance</h3>")
		// 1. ASCII tree inside <pre> so spacing is preserved.
		sb.WriteString(`<pre class="inheritance-tree">`)
		sb.WriteString(html.EscapeString(c.renderInheritanceTree()))
		sb.WriteString("</pre>")
		// 2. Flattened linearization (single line). The renderer returns
		// backtick-wrapped names already; we don't escape backticks (they're
		// safe in HTML) so consumers that style on <code>-look survive.
		sb.WriteString(`<p class="inheritance-flat"><strong>Flattened (derived → base):</strong> `)
		sb.WriteString(html.EscapeString(c.renderInheritanceFlattened()))
		sb.WriteString("</p>")
		// 3. Interactive Mermaid/vis.js diagram.
		sb.WriteString(fmt.Sprintf(`<div class="network-container" data-raw="%s"></div>`, strings.ReplaceAll(c.InheritanceMermaid, "\"", "&quot;")))
	} else if len(c.InheritanceChain) > 1 {
		// Fallback when there are no recorded edges (single base, etc.).
		sb.WriteString("<h3>Inheritance Chain</h3>")
		sb.WriteString(`<p class="inheritance-flat"><strong>Flattened (derived → base):</strong> `)
		sb.WriteString(html.EscapeString(c.renderInheritanceFlattened()))
		sb.WriteString("</p>")
	}

	// Entry Functions (Per-function graphs)
	if len(c.EntryFunctions) > 0 {
		sb.WriteString("<h3>Entry Functions</h3>")

		// Group functions
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

		renderGroup := func(isAccessControlled bool, label string) {
			groups := grouped[isAccessControlled]
			if len(groups) == 0 {
				return
			}

			sb.WriteString(fmt.Sprintf("<h4>%s</h4>", label))

			// 1. Check self
			if fns, ok := groups["_self_"]; ok {
				sb.WriteString("<h5>Defined in <em>self</em></h5>")
				for _, fn := range fns {
					c.renderEntryFunctionHTML(&sb, fn)
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
				sb.WriteString(fmt.Sprintf("<h5>Defined in <em>%s</em></h5>", html.EscapeString(k)))
				for _, fn := range groups[k] {
					c.renderEntryFunctionHTML(&sb, fn)
				}
			}
		}

		renderGroup(true, "🔒 Access Controlled")
		renderGroup(false, "🔓 Unprotected")
	}

	// View Functions
	if len(c.ViewFunctions) > 0 {
		sb.WriteString("<h3>View Functions</h3>")
		sb.WriteString("<details><summary>Show view functions</summary>")
		sb.WriteString("<table>")
		sb.WriteString("<thead><tr><th>Name</th><th>Signature</th><th>Defined In</th></tr></thead>")
		sb.WriteString("<tbody>")
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
			sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td><code>%s</code></td><td>%s</td></tr>", html.EscapeString(name), html.EscapeString(sig), html.EscapeString(definedIn)))
		}
		sb.WriteString("</tbody></table></details>")
	}

	// Internal Functions
	if len(c.InternalFunctions) > 0 {
		sb.WriteString("<h3>Internal Functions</h3>")
		sb.WriteString("<details><summary>Show internal functions</summary>")
		sb.WriteString("<table>")
		sb.WriteString("<thead><tr><th>Name</th><th>Signature</th><th>Defined In</th></tr></thead>")
		sb.WriteString("<tbody>")
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
			sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td><code>%s</code></td><td>%s</td></tr>", html.EscapeString(name), html.EscapeString(sig), html.EscapeString(definedIn)))
		}
		sb.WriteString("</tbody></table></details>")
	}

	// State Variables
	if len(c.StateVariables) > 0 {
		sb.WriteString("<h3>State Variables</h3>")
		sb.WriteString("<details><summary>Show state variables</summary>")
		sb.WriteString("<table>")
		sb.WriteString("<thead><tr><th>Name</th><th>Type</th><th>Defined In</th></tr></thead>")
		sb.WriteString("<tbody>")
		for _, sv := range c.StateVariables {
			definedIn := sv.DefinedIn
			if definedIn == c.Name {
				definedIn = "*self*"
			}
			sb.WriteString(fmt.Sprintf("<tr><td><code>%s</code></td><td><code>%s</code></td><td>%s</td></tr>", html.EscapeString(sv.Name), html.EscapeString(sv.TypeName), html.EscapeString(definedIn)))
		}
		sb.WriteString("</tbody></table></details>")
	}

	sb.WriteString("</div>") // End card
	return sb.String()
}

// renderEntryFunctionHTML renders a single entry function in HTML
func (c *ContractSummary) renderEntryFunctionHTML(sb *strings.Builder, fn *FunctionSummary) {
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

	sb.WriteString(`<details>`)
	// Format: name - signature (modifier list)
	sb.WriteString(fmt.Sprintf(`<summary>%s - <code>%s</code>%s%s</summary>`,
		html.EscapeString(selector), html.EscapeString(sig), payable, html.EscapeString(modStr)))

	if fn.CallGraphMermaid != "" && strings.Contains(fn.CallGraphMermaid, "-->") {
		// Full HTML-escape (not just quotes) so a contract/function name in the
		// Mermaid source can't break out of the data-raw attribute.
		sb.WriteString(fmt.Sprintf(`<div class="network-container" data-raw="%s"></div>`, html.EscapeString(fn.CallGraphMermaid)))
		sb.WriteString(`<p><small><em>Click "Full Screen" to view details.</em></small></p>`)
	} else {
		sb.WriteString("<p><em>No internal calls</em></p>")
	}
	sb.WriteString(`</details>`)
}
