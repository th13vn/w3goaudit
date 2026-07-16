package report

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/engine"
)

// encodeURIPath percent-encodes each segment of a slash-separated path so the
// result is a valid URI component (e.g. a space becomes %20). Slashes are
// preserved as path separators. SARIF consumers reject invalid file:// URIs.
func encodeURIPath(slashPath string) string {
	parts := strings.Split(slashPath, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// SARIF 2.1.0 emitter. Schema:
//   https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
//
// Consumed by GitHub Code Scanning, Defect Dojo, SonarQube, and most
// enterprise SAST aggregators. We only emit the subset of fields these
// tools actually read; everything optional that adds noise is skipped.

// FormatFindingsAsSARIF serializes findings to a SARIF 2.1.0 JSON document.
//
// projectRoot is the directory used to build relative paths for
// `artifactLocation.uri` so the SARIF stays portable across runners (CI
// uploads from a Linux container reading paths that don't exist on a
// GitHub Code Scanning Windows VM). Pass "" to fall back to absolute paths.
//
// Each unique TemplateID becomes one rules entry; each finding becomes one
// result entry pointing at its rule by ruleId. Severity-score metadata is
// surfaced under properties so GitHub's security tab and other consumers can
// filter on it.
func FormatFindingsAsSARIF(findings []*engine.Finding, tool ToolMeta, projectRoot string) (string, error) {
	rules := buildSarifRules(findings)
	results := buildSarifResults(findings, projectRoot)

	run := map[string]interface{}{
		"columnKind": "unicodeCodePoints",
		"tool": map[string]interface{}{
			"driver": map[string]interface{}{
				"name":           tool.Name,
				"version":        tool.Version,
				"informationUri": "https://github.com/th13vn/w3goaudit",
				"rules":          rules,
			},
		},
		"results": results,
	}

	// When a projectRoot is supplied, declare it as the srcRoot URI base so
	// downstream tools can resolve relative `uri`s back to a workspace path.
	if projectRoot != "" {
		run["originalUriBaseIds"] = map[string]interface{}{
			"srcRoot": map[string]string{"uri": pathToFileURI(projectRoot)},
		}
	}

	doc := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs":    []map[string]interface{}{run},
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encoding SARIF: %w", err)
	}
	return string(out), nil
}

// pathToFileURI converts an absolute filesystem path to a `file://` URI with
// trailing slash, suitable for SARIF originalUriBaseIds.
func pathToFileURI(p string) string {
	clean := filepath.ToSlash(p)
	if !strings.HasSuffix(clean, "/") {
		clean += "/"
	}
	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}
	return "file://" + encodeURIPath(clean)
}

// sarifArtifactURI returns the file URI to embed under
// `artifactLocation.uri`. When projectRoot is set and the file lives below
// it, returns a *relative* URI; otherwise returns the absolute path. Empty
// projectRoot keeps the legacy absolute-path behaviour.
func sarifArtifactURI(absFile, projectRoot string) (uri, uriBaseId string) {
	if projectRoot == "" || absFile == "" {
		return encodeURIPath(filepath.ToSlash(absFile)), ""
	}
	rel, err := filepath.Rel(projectRoot, absFile)
	if err != nil || strings.HasPrefix(rel, "..") {
		// File lives outside the project root — fall back to absolute path.
		return encodeURIPath(filepath.ToSlash(absFile)), ""
	}
	return encodeURIPath(filepath.ToSlash(rel)), "srcRoot"
}

// buildSarifRules emits one rule object per unique TemplateID seen in findings.
// Rules carry the human-readable description and default severity. Severity maps
// to SARIF's "level" via sarifLevelFor (note/warning/error) — consumers compute
// their own threshold from properties.security-severity.
func buildSarifRules(findings []*engine.Finding) []map[string]interface{} {
	seen := make(map[string]bool)
	rules := make([]map[string]interface{}, 0)

	for _, f := range findings {
		if seen[f.TemplateID] {
			continue
		}
		seen[f.TemplateID] = true

		rule := map[string]interface{}{
			"id":   f.TemplateID,
			"name": f.TemplateID,
			"shortDescription": map[string]string{
				"text": fallback(f.Title, f.TemplateID),
			},
			"fullDescription": map[string]string{
				"text": fallback(f.Message, fallback(f.Title, f.TemplateID)),
			},
			"defaultConfiguration": map[string]string{
				"level": sarifLevelFor(f.Severity),
			},
		}

		// Help text: combine recommendation + fix when present.
		help := buildHelpText(f)
		if help != "" {
			rule["help"] = map[string]string{"text": help, "markdown": help}
		}

		// Properties: tags + security-severity score (consumed by GitHub).
		props := map[string]interface{}{}
		tags := []string{"security"}
		props["tags"] = tags
		props["security-severity"] = sarifSecuritySeverity(f.Severity)
		rule["properties"] = props

		rules = append(rules, rule)
	}

	return rules
}

// buildSarifResults emits one result per finding, pointing back to its rule.
// projectRoot enables relative `artifactLocation.uri` + `uriBaseId: srcRoot`,
// which is what GitHub Code Scanning and other SARIF consumers expect.
// sarifRegion builds a SARIF region from a finding location, emitting the
// precise 1-based column fields (v0.4) when the matched node supplied them so
// consumers like GitHub Code Scanning can highlight the exact range instead of
// a whole line. startColumn/endColumn are 1-based half-open, matching the SARIF
// spec directly (endColumn is the column just past the region).
//
// charOffset/charLength are deliberately NOT emitted: our byte offsets are
// UTF-8 byte offsets, while SARIF charOffset/charLength are character offsets —
// they diverge whenever non-ASCII precedes the finding. The line/column region
// is unambiguous and sufficient; emitting byte offsets as char offsets would
// send viewers to the wrong place.
func sarifRegion(loc engine.Location) map[string]interface{} {
	region := map[string]interface{}{"startLine": maxInt(loc.Line, 1)}
	if loc.Col > 0 {
		region["startColumn"] = loc.Col
	}
	if loc.EndLine > 0 {
		region["endLine"] = loc.EndLine
	}
	if loc.EndCol > 0 {
		region["endColumn"] = loc.EndCol
	}
	return region
}

func buildSarifResults(findings []*engine.Finding, projectRoot string) []map[string]interface{} {
	results := make([]map[string]interface{}, 0, len(findings))
	for _, f := range findings {
		msg := fallback(f.Message, fallback(f.Title, f.TemplateID))

		uri, uriBaseId := sarifArtifactURI(f.Location.File, projectRoot)
		artifactLoc := map[string]interface{}{"uri": uri}
		if uriBaseId != "" {
			artifactLoc["uriBaseId"] = uriBaseId
		}

		result := map[string]interface{}{
			"ruleId":  f.TemplateID,
			"level":   sarifLevelFor(f.Severity),
			"message": map[string]string{"text": msg},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": artifactLoc,
						"region":           sarifRegion(f.Location),
					},
				},
			},
		}

		// Logical location (contract/function) — useful for grouping in dashboards.
		// Only join with a dot when BOTH parts are non-empty, so a contract-
		// scope finding doesn't produce `"MyToken."` (invalid FQN).
		if f.Location.Contract != "" || f.Location.Function != "" {
			logical := map[string]interface{}{}
			if f.Location.Function != "" {
				logical["name"] = f.Location.Function
				logical["kind"] = "function"
			} else {
				logical["name"] = f.Location.Contract
				logical["kind"] = "type"
			}
			switch {
			case f.Location.Contract != "" && f.Location.Function != "":
				logical["fullyQualifiedName"] = f.Location.Contract + "." + f.Location.Function
			case f.Location.Contract != "":
				logical["fullyQualifiedName"] = f.Location.Contract
			case f.Location.Function != "":
				logical["fullyQualifiedName"] = f.Location.Function
			}
			result["locations"].([]map[string]interface{})[0]["logicalLocations"] = []map[string]interface{}{logical}
		}

		// Reachability path -> SARIF relatedLocations. Each call-chain hop
		// becomes one relatedLocation so SARIF consumers (GitHub Code
		// Scanning, IDE viewers) can render the full path the finding
		// traversed from an external entry to the dangerous statement.
		if f.Reachability != nil && len(f.Reachability.Steps) > 0 {
			related := make([]map[string]interface{}, 0, len(f.Reachability.Steps))
			for i, s := range f.Reachability.Steps {
				// Each hop renders at its own file. Cross-contract chains
				// otherwise point every intermediate step at the primary
				// file's byte offsets, sending SARIF viewers to the wrong file.
				hopLoc := artifactLoc
				if s.File != "" && s.File != f.Location.File {
					hUri, hBase := sarifArtifactURI(s.File, projectRoot)
					hopLoc = map[string]interface{}{"uri": hUri}
					if hBase != "" {
						hopLoc["uriBaseId"] = hBase
					}
				}
				phys := map[string]interface{}{
					"artifactLocation": hopLoc,
					"region": map[string]interface{}{
						"startLine": maxInt(s.Line, 1),
					},
				}
				stepFQN := s.Function
				if s.Contract != "" && s.Function != "" {
					stepFQN = s.Contract + "." + s.Function
				}
				kindLabel := "hop"
				if i == 0 {
					kindLabel = "entry"
				} else if i == len(f.Reachability.Steps)-1 {
					kindLabel = "host"
				}
				related = append(related, map[string]interface{}{
					"id":               i,
					"physicalLocation": phys,
					"message":          map[string]string{"text": kindLabel + ": " + stepFQN},
				})
			}
			result["relatedLocations"] = related
		}

		// EntryPoint -> result.properties.entryPoint. GitHub Code Scanning
		// surfaces properties in the issue body; this is the auditor-actionable
		// fix-here pointer.
		if f.EntryPoint != nil {
			props, _ := result["properties"].(map[string]interface{})
			if props == nil {
				props = map[string]interface{}{}
				result["properties"] = props
			}
			ep := map[string]interface{}{
				"contract": f.EntryPoint.Contract,
				"function": f.EntryPoint.Function,
			}
			if f.EntryPoint.AuthVerdict != "" {
				ep["authVerdict"] = f.EntryPoint.AuthVerdict
			}
			if len(f.EntryPoint.AuthReasons) > 0 {
				ep["authReasons"] = f.EntryPoint.AuthReasons
			}
			props["entryPoint"] = ep
		}

		// PrimaryAST -> result.properties.primaryAst, so IDE viewers can jump
		// to the matched node's kind / range.
		if f.PrimaryAST != nil {
			props, _ := result["properties"].(map[string]interface{})
			if props == nil {
				props = map[string]interface{}{}
				result["properties"] = props
			}
			node := map[string]interface{}{"kind": f.PrimaryAST.Kind, "startLine": f.PrimaryAST.Start}
			if f.PrimaryAST.Name != "" {
				node["name"] = f.PrimaryAST.Name
			}
			if f.PrimaryAST.End != 0 {
				node["endLine"] = f.PrimaryAST.End
			}
			if f.PrimaryAST.StartCol > 0 {
				node["startColumn"] = f.PrimaryAST.StartCol
			}
			if f.PrimaryAST.EndCol > 0 {
				node["endColumn"] = f.PrimaryAST.EndCol
			}
			props["primaryAst"] = node
		}

		results = append(results, result)
	}
	return results
}

// sarifLevelFor maps W3GoAudit severity to SARIF level enum.
// SARIF accepts: none, note, warning, error.
func sarifLevelFor(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "INFO":
		return "note"
	default:
		return "none"
	}
}

// sarifSecuritySeverity returns the GitHub-recognized security-severity score
// (CVSS-style 0–10). Used by GitHub Code Scanning to compute alert priority.
func sarifSecuritySeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "9.5"
	case "HIGH":
		return "7.5"
	case "MEDIUM":
		return "5.0"
	case "LOW":
		return "3.0"
	case "INFO":
		return "1.0"
	default:
		return "0.0"
	}
}

func buildHelpText(f *engine.Finding) string {
	var parts []string
	if f.Recommendation != "" {
		parts = append(parts, "Recommendation: "+f.Recommendation)
	}
	if f.Fix != "" {
		parts = append(parts, "Fix: "+f.Fix)
	}
	if len(f.References) > 0 {
		parts = append(parts, "References: "+strings.Join(f.References, ", "))
	}
	return strings.Join(parts, "\n\n")
}

func fallback(s, alt string) string {
	if s != "" {
		return s
	}
	return alt
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
