package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/engine"
)

// contractReportIndex is the immutable path plan shared by bundle writers and
// manifest generation. Reports are keyed by exact source/name identity.
type contractReportIndex struct {
	refs    []ContractRef
	reports map[string]string
}

type contractReportCandidate struct {
	contract *ContractSummary
	relSrc   string
	path     string
	key      string
}

// buildContractReportIndex plans every report path before result-folder
// cleanup or writing. Findings are used only for the manifest tally.
func buildContractReportIndex(summary *SummaryReport, findings []*engine.Finding) (contractReportIndex, error) {
	return buildContractReportIndexWithDigest(summary, findings, identityDigest)
}

func buildContractReportIndexWithDigest(summary *SummaryReport, findings []*engine.Finding, digestFor func(string) string) (contractReportIndex, error) {
	idx := contractReportIndex{reports: make(map[string]string)}
	if summary == nil {
		return idx, fmt.Errorf("building contract report index: nil summary")
	}

	candidates := make([]contractReportCandidate, 0, len(summary.MainContracts))
	for _, contract := range summary.MainContracts {
		if contract == nil {
			continue
		}
		candidates = append(candidates, contractReportCandidate{
			contract: contract,
			relSrc:   normalizedContractSource(summary.ProjectRoot, contract.SourceFile),
			path:     contractReportPath(summary.ProjectRoot, contract),
			key:      contractIdentityKey(contract),
		})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].relSrc != candidates[j].relSrc {
			return candidates[i].relSrc < candidates[j].relSrc
		}
		if candidates[i].contract.Name != candidates[j].contract.Name {
			return candidates[i].contract.Name < candidates[j].contract.Name
		}
		return candidates[i].key < candidates[j].key
	})

	byCandidate := make(map[string][]int)
	for i, candidate := range candidates {
		key := portableReportPathKey(candidate.path)
		byCandidate[key] = append(byCandidate[key], i)
	}
	for _, members := range byCandidate {
		if len(members) == 1 {
			continue
		}
		shortHashes := make(map[string][]int)
		for _, member := range members {
			hash := digestFor(candidates[member].key)
			if len(hash) < 16 {
				return idx, fmt.Errorf("contract report digest for %q has length %d, want at least 16", candidates[member].key, len(hash))
			}
			shortHashes[hash[:16]] = append(shortHashes[hash[:16]], member)
		}
		for short, hashedMembers := range shortHashes {
			if len(hashedMembers) == 1 {
				member := hashedMembers[0]
				candidates[member].path = appendPathDigest(candidates[member].path, short)
				continue
			}
			fullHashes := make(map[string][]int)
			for _, member := range hashedMembers {
				hash := digestFor(candidates[member].key)
				fullHashes[hash] = append(fullHashes[hash], member)
			}
			for full, fullMembers := range fullHashes {
				if len(fullMembers) > 1 {
					return idx, fmt.Errorf("contract report path collision after full digest %s for %q", full, candidates[fullMembers[0]].path)
				}
				member := fullMembers[0]
				candidates[member].path = appendPathDigest(candidates[member].path, full)
			}
		}
	}

	seen := make(map[string]string, len(candidates))
	idx.refs = make([]ContractRef, 0, len(candidates))
	for _, candidate := range candidates {
		portableKey := portableReportPathKey(candidate.path)
		if previous, ok := seen[portableKey]; ok {
			return idx, fmt.Errorf("contract report path collision: %q for %q and %q", candidate.path, previous, candidate.key)
		}
		seen[portableKey] = candidate.key
		idx.reports[candidate.key] = candidate.path
		idx.refs = append(idx.refs, ContractRef{
			Name:     candidate.contract.Name,
			Source:   candidate.relSrc,
			Dir:      path.Dir(candidate.path),
			Report:   candidate.path,
			Findings: len(findingsForContract(findings, candidate.contract)),
		})
	}
	return idx, nil
}

// portableReportPathKey models the case-insensitive path aliases used by
// Windows and common macOS filesystems. Sanitized report paths are ASCII, so
// lowercase comparison is sufficient to prevent one report overwriting
// another when a bundle is moved between supported platforms.
func portableReportPathKey(reportPath string) string {
	return strings.ToLower(reportPath)
}

func contractIdentityKey(contract *ContractSummary) string {
	return contract.SourceFile + "\x00" + contract.Name
}

func identityDigest(identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(digest[:])
}

func appendPathDigest(candidate, digest string) string {
	ext := path.Ext(candidate)
	base := strings.TrimSuffix(candidate, ext)
	return base + "__" + digest + ext
}

// contractReportPath returns an unsuffixed path. The index adds an identity
// digest only when multiple contracts sanitize to the same candidate.
func contractReportPath(projectRoot string, contract *ContractSummary) string {
	if contract == nil {
		return path.Join("contracts", "unnamed__unnamed.md")
	}
	relSrc := normalizedContractSource(projectRoot, contract.SourceFile)
	ext := path.Ext(relSrc)
	withoutExt := strings.TrimSuffix(relSrc, ext)
	parts := strings.Split(withoutExt, "/")
	for i, part := range parts {
		parts[i] = sanitizeReportComponent(part)
	}
	stem := parts[len(parts)-1]
	dir := parts[:len(parts)-1]
	base := stem + "__" + sanitizeReportComponent(contract.Name) + ".md"
	return path.Join(append([]string{"contracts"}, append(dir, base)...)...)
}

func normalizedContractSource(projectRoot, sourceFile string) string {
	rel := strings.ReplaceAll(relPathForReport(projectRoot, sourceFile), "\\", "/")
	rel = strings.TrimPrefix(path.Clean("/"+rel), "/")
	if rel == "." || rel == "" || rel == ".." || strings.HasPrefix(rel, "../") {
		rel = path.Base(sourceFile)
	}
	return rel
}

func sanitizeReportComponent(component string) string {
	component = sanitizeName(component)
	if isWindowsDeviceName(strings.ToLower(component)) {
		component += "_"
	}
	if len(component) > 96 {
		digest := identityDigest(component)
		component = component[:77] + "__" + digest[:16]
	}
	return component
}

func isWindowsDeviceName(component string) bool {
	if component == "con" || component == "prn" || component == "aux" || component == "nul" {
		return true
	}
	if len(component) == 4 && (strings.HasPrefix(component, "com") || strings.HasPrefix(component, "lpt")) {
		return component[3] >= '1' && component[3] <= '9'
	}
	return false
}
