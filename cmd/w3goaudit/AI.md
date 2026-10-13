# cmd/w3goaudit – CLI

Cobra entry point. w3goaudit path is the scan; there is no scan subcommand.
The command composes Reader, Builder, Database, Engine, and Report.

## Key files

| File | Responsibility |
|---|---|
| root.go | Root flags, version, config |
| scan_options.go | Immutable scan options and execution |
| output_safety.go | Source/output boundary and symlink checks |
| scan_console.go | Progress and console output |
| helpers.go | Source/cache loading, logger, warnings |
| build.go | Database-only build command |
| extract*.go | Source, context, workflow, bundle, and diff extracts |
| config_cli.go | Config and template update handling |
| scan_filters.go | Template and severity filters |
| completion.go | Shell completion |
| update.go | Self-update |

## Invariants

- RunE errors reach exit code 1, including report-write failures.
- --stdout/-q writes only the summary and creates no result folder.
- Warnings go to stderr; machine-readable stdout stays clean.
- Source and database scans share strict-import, strict-parse, diagnostics, and location behavior.
- Output cannot overlap the source scope, including symlink aliases. Managed paths are reset before exclusive creation.
- Matched-node location is the default; verifier is the compatibility alternative.
- Version in root.go is the single version source; current release is v0.7.0, paired with template pack v3.0.1.

## Change checklist

Update README.md, docs/usage.md, and this file for CLI changes. Update docs/workflows.md and docs/extension-output.md when output changes. Add focused command tests and run the root verification gates.
