# w3goaudit project map

## Purpose

w3goaudit is a Go CLI and SDK for static analysis of Solidity projects. It reads Solidity sources, builds a deterministic contract database, executes WQL templates, and writes findings plus evidence for humans and editor tools.

## Pipeline

Reader -> Builder -> Database -> Engine -> Report

- reader discovers sources, project roots, imports, remappings, and git data.
- builder parses sources and builds AST, inheritance, call graph, effects, type, authorization, transaction-context, and external-boundary facts.
- types owns the serialized database and stable identities.
- engine validates and executes canonical WQL templates.
- report writes Markdown, HTML, SARIF, JSON artifacts, and contract deep dives.
- cmd/w3goaudit composes the pipeline and exposes the CLI.

## Package map

| Path | Responsibility | Guide |
|---|---|---|
| cmd/w3goaudit/ | CLI, scan/build/extract commands, output safety | cmd/w3goaudit/AI.md |
| pkg/reader/ | Source discovery and import resolution | pkg/reader/AI.md |
| pkg/logging/ | Scan-local serialized logging | pkg/logging/AI.md |
| pkg/builder/ | Database construction and semantic facts | pkg/builder/AI.md |
| pkg/types/ | Database, AST, identities, and fact schemas | pkg/types/AI.md |
| pkg/engine/ | WQL loading, validation, matching, findings | pkg/engine/AI.md |
| pkg/report/ | Result folders, JSON, Markdown, HTML, SARIF | pkg/report/AI.md |
| pkg/home/ | User config and template home | pkg/home/AI.md |
| templates/ | Embedded official WQL detector pack | templates/AI.md |
| test-data/ | Security and core fixtures | test-data/README.md |
| scripts/benchmark/ | Maintainer-local benchmark harness; ignored in fresh clones | scripts/benchmark/README.md |
| scripts/solodit-etl/ | Standalone ingestion and publishing service | scripts/solodit-etl/AI.md |

## Current invariants

- Core v0.7.0 pairs with official pack v3.0.1. Private candidate and incident lanes are ignored, not embedded, and excluded from published history and release archives.

- The root command is the scan: w3goaudit path. There is no scan subcommand.
- Use the Go version declared in go.mod. Do not duplicate it in scripts or docs.
- Function.Selector is canonical text such as transfer(address,uint256); Function.Signature is the four-byte Keccak value.
- Source columns are one-based Unicode code points. Byte offsets are zero-based UTF-8 ranges. Both end positions are half-open and neither is an LSP position.
- Exact contract identity is absPath#Contract; function identity includes the canonical selector. Never resolve duplicate names by map order.
- Parse loss is loud. parse.recovered and parse.skipped diagnostics appear in stderr and report output. --strict-parse fails before report generation.
- Output cannot overlap the selected source scope, including symlink aliases. Managed report paths are reset before exclusive creation.
- WQL is canonical select/from/where, or one-level and/or composition. Unknown keys, merge keys, malformed required values, and unsupported aliases fail closed.
- Template loading is fail-closed unless lenient loading is explicitly enabled.
- The scanner has no model transport, credentials, AI callback, or AI review artifact. It emits deterministic evidence for external consumers.
- A normal scan writes README.md, audit.md, results.sarif, run.log, data JSON, and one Markdown deep dive per main contract. --html adds audit.html.
- Versioned fact surfaces include authorization, transaction context, and external boundaries. See docs/extension-output.md and docs/internals.md.

## Documentation map

- README.md: quick start and command overview.
- docs/usage.md: complete CLI usage, flags, artifacts, and troubleshooting.
- docs/workflows.md: scan/build/report pipeline.
- docs/project-overview.md: architecture and design decisions.
- docs/internals.md: implementation and precision details.
- docs/sdk.md: Go SDK/API reference.
- docs/wql-syntax.md: WQL authoring reference.
- docs/extension-output.md: editor-facing JSON artifacts.

Historical design and research records live under .vscode/specs/, .vscode/plans/, and .vscode/reports/. The active handoff is .vscode/.ai/STATUS.md; the append-only work log is .vscode/.ai/JOURNAL.md.

## Change checklist

1. Read the relevant package AI.md and canonical user-facing guide.
2. Add or update focused tests before changing behavior.
3. Update every touched package guide and relevant canonical docs.
4. Preserve source/cache parity, deterministic ordering, and exact identities.
5. Run the focused test, then the full gates below.
6. Rebuild the root w3goaudit binary after verification. Do not commit it.

## Verification

Run gofmt, go mod tidy -diff, go test -count=1 ./..., go test -race -count=1 ./..., go test -shuffle=on -count=3 ./..., go vet ./..., staticcheck ./..., test -z "$(gocyclo -over 35 cmd pkg)", go build -trimpath -o w3goaudit ./cmd/w3goaudit, and ./w3goaudit --version.

For release or report changes, also run the official fixture scan and the maintainer-local competitive gate described in docs/usage.md.
