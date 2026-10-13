# pkg/report – result generation

Turns findings and the database into a deterministic result folder for humans,
CI, and editor consumers. The package owns Markdown, HTML, SARIF, JSON data,
contract deep dives, extraction bundles, and manifest indexing.

## Key files

| File | Responsibility |
|---|---|
| generator.go | Top-level report orchestration |
| bundle.go | Result-folder creation and managed paths |
| manifest.go | Artifact index, counts, versions, references |
| folder_docs.go, project_docs.go, contract_docs.go | Markdown reports |
| markdown.go, html.go, audit_html.go | Human-readable rendering |
| sarif.go | SARIF 2.1.0 output |
| scan_formats.go, console.go | Console and format policy |
| diagnostics.go | Analysis-quality diagnostics |
| interactions.go, hunter.go, authorization.go | Semantic evidence |
| nav.go, explorer.go, xref.go | Extension-facing indexes |
| state_matrix.go | State/effect evidence |
| code_extract.go | Source/context/workflow extraction |

## Result contract

A normal scan writes README.md, audit.md, results.sarif, run.log,
data/manifest.json, database.json, findings.json, overview.json,
diagnostics.json, versioned evidence, extension indexes, and one Markdown deep
dive per main contract. --html adds only audit.html.

Manifest discovery is canonical. Timestamps may vary, but ordering, identities,
findings, evidence, and references are deterministic. Portable URIs are relative
to srcRoot; absolute checkout paths do not belong in portable artifacts.

Finding locations identify the matched statement by default. Entry hops travel
in entryPoint and reachability. SARIF declares columnKind unicodeCodePoints.
Managed paths are reset before exclusive creation. The output folder cannot
overlap the source scope.

## Change checklist

The release documentation gate in docs_layout_test.go pins the current v0.7.0
CLI version and changelog heading alongside result-layout promises.

Update docs/workflows.md, docs/extension-output.md, README artifact lists, and
relevant package/type indexes for output changes. Add round-trip, determinism,
source/cache, SARIF, and offline HTML tests as needed.
