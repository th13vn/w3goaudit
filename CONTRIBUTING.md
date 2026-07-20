# Contributing to w3goaudit

Thanks for your interest! w3goaudit is a Go static-analysis engine for Solidity
with a YAML-based detection language (WQL). The most valuable contributions are
**new detectors** — and you can write one without touching Go.

## Ground rules

- Discuss non-trivial changes in an issue first.
- Every code change must keep `go build ./...`, `go test ./...`, `go vet ./...`,
  and `gofmt -l ./cmd ./pkg ./templates` (empty output) green.
- Update the relevant `INDEX.md` and `docs/` when you change behavior — each
  `pkg/*` and top-level folder with an `INDEX.md` documents its own change
  checklist; see `docs/project-overview.md` for the overall architecture.
- New detectors **and** engine changes need tests (vulnerable + safe fixtures).

## Dev setup

Use the Go version declared by `go.mod` (currently Go 1.26.5); local and
external automation should read the same file rather than maintaining a second
version string. This is a security-driven minimum: the standard-library fixes
required by govulncheck need Go >=1.25.12.

```bash
git clone https://github.com/th13vn/w3goaudit
cd w3goaudit
go build -o w3goaudit ./cmd/w3goaudit
go test ./...
```

## Release gates

Before opening a PR or cutting a release, run the gates relevant to your change
locally or in user-owned external automation: `gofmt`, `go mod tidy -diff`,
`go vet`, staticcheck v0.6.1 and gocyclo v0.6.0 (`-over 35 cmd pkg` must be
empty), Markdown link validation plus its unit tests, normal/race/shuffled Go
tests, host and Linux ARM64 builds, govulncheck v1.1.4, an official-template
scan with manifest/JSON/SARIF/offline-HTML artifact validation, and the Docker
Compose competitive benchmark.

```bash
docker compose -f benchmarks/compose.yaml run --rm benchmark
```

Docker Compose is the only supported benchmark host entry point; the image
contains the pinned scanners and derives and verifies its Go version directly
from `go.mod`. The gate recomputes metrics from raw counts and requires
precision at least 0.65, recall at least 0.95, and zero failed cases. The
Dockerfile also verifies the reviewed generated-lock hash for its pinned
4naly3er commit.

## Write your first detector in 5 minutes

A WQL document is meta plus one query: block. Example: flag
`block.timestamp` used inside a `require` (a weak time guard).

1. **Write the template** — `templates/official/medium/timestamp-guard.yaml`
   (official templates live under a `critical/`, `high/`, or `medium/` severity
   subdirectory), in
   **WQL** (`query:` containing `select`/`from`/`where` — the syntax used by all 106
   official/benchmark/feature-test templates):

   ```yaml
   meta:
     id: SEC-TIME-001
     title: block.timestamp used in a require guard
     severity: MEDIUM
     confidence: MEDIUM
     description: >
       block.timestamp is miner-influenceable; using it directly in a guard can
       be gamed within a ~15s window.
     recommendation: Avoid timestamp-based guards for security-critical checks.

   query:
     select: member        # expr.member_access
     from: function
     where:
       - name: "block\\.timestamp"
       - in: { block: require }   # nested inside a require(...) guard
   ```

   See `docs/wql-syntax.md` for the full `select`/`from`/`where` reference
   (block-kind, attribute, and preset catalogs, plus query-level `and:`/`or:`
   composition), and the existing `templates/official/` tree for idiomatic
   examples. WQL (`meta` plus one `query:` block) is the only accepted public YAML
   schema; unknown keys are rejected at load.

2. **Write fixtures** — `test-data/security/timestamp-guard.sol` with a
   `Vulnerable*` contract that should match and a `Safe*` contract that must
   not (to prove you didn't introduce a false positive).

3. **Run it:**

   ```bash
   go build -o w3goaudit ./cmd/w3goaudit
   ./w3goaudit test-data/security/timestamp-guard.sol \
     --template templates/official/medium/timestamp-guard.yaml
   ```

   Confirm only the `Vulnerable*` contract is flagged. Bad templates fail fast
   at load with an actionable message (unknown block kind/preset/attribute,
   `select` omitted with no AST-level matcher in `where`, invalid regex, etc.).

4. **Document** — add the detector to `templates/INDEX.md`.

5. **Open a PR** with the template, fixtures, and INDEX entry.

## Engine / Go changes

Read the package `INDEX.md` for whatever you touch first (every `pkg/*` has
one). Common entry points:

- AST kinds / parsing — `pkg/builder/ast_builder.go`, `pkg/types/ast.go`
- WQL operators / matchers — `pkg/engine/template.go`, `pkg/engine/verify.go`
- Report formats — `pkg/report/`
- CLI flags — `cmd/w3goaudit/`

Public template YAML contains `meta` plus one `query:` block. Internally,
lowering compiles that WQL into evaluator `Template`/`QueryBlock`/`Rule` IR;
when changing that IR, keep its context `filter` and AST `match` layers cleanly
separated because validation and execution depend on the distinction.

## Reporting bugs

False positives / negatives: open an issue with the minimal Solidity input, the
template/command, what you expected, and what you got. For vulnerabilities in
the tool itself, see [SECURITY.md](./SECURITY.md).
