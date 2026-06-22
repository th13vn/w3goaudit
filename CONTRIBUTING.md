# Contributing to w3goaudit

Thanks for your interest! w3goaudit is a Go static-analysis engine for Solidity
with a YAML-based detection language (WQL). The most valuable contributions are
**new detectors** — and you can write one without touching Go.

## Ground rules

- Discuss non-trivial changes in an issue first.
- Every code change must keep `go build ./...`, `go test ./...`, `go vet ./...`,
  and `gofmt -l ./cmd ./pkg ./templates` (empty output) green. CI enforces this.
- Update the relevant `INDEX.md` and `docs/` when you change behavior — each
  `pkg/*` and top-level folder with an `INDEX.md` documents its own change
  checklist; see `docs/project-overview.md` for the overall architecture.
- New detectors **and** engine changes need tests (vulnerable + safe fixtures).

## Dev setup

```bash
git clone https://github.com/th13vn/w3goaudit
cd w3goaudit
go build -o w3goaudit ./cmd/w3goaudit
go test ./...
```

## Write your first detector in 5 minutes

A WQL detector is a YAML file with metadata + a query. Example: flag
`block.timestamp` used inside a `require` (a weak time guard).

1. **Write the template** — `templates/official/timestamp-guard.yaml`:

   ```yaml
   meta:
     id: SEC-TIME-001
     title: block.timestamp used in a require guard
     severity: LOW
     confidence: MEDIUM
     description: >
       block.timestamp is miner-influenceable; using it directly in a guard can
       be gamed within a ~15s window.
     recommendation: Avoid timestamp-based guards for security-critical checks.

   query:
     scope: function
     match:
       contains:
         kind: expr.member_access
         name: "block\\.timestamp"
         inside:
           kind: check.require
   ```

   See `docs/wql-syntax.md` for the full operator/kind/attribute reference, and
   the existing `templates/official/*.yaml` for idiomatic examples.

2. **Write fixtures** — `test-data/security/timestamp-guard.sol` with a
   `Vulnerable*` contract that should match and a `Safe*` contract that must
   not (to prove you didn't introduce a false positive).

3. **Run it:**

   ```bash
   go build -o w3goaudit ./cmd/w3goaudit
   ./w3goaudit test-data/security/timestamp-guard.sol \
     --template templates/official/timestamp-guard.yaml
   ```

   Confirm only the `Vulnerable*` contract is flagged. Bad templates fail fast
   at load with an actionable message (unknown kind/preset/scope, AST field in
   `filter:`, invalid regex, etc.).

4. **Document** — add the detector to `templates/INDEX.md`.

5. **Open a PR** with the template, fixtures, and INDEX entry.

## Engine / Go changes

Read the package `INDEX.md` for whatever you touch first (every `pkg/*` has
one). Common entry points:

- AST kinds / parsing — `pkg/builder/ast_builder.go`, `pkg/types/ast.go`
- WQL operators / matchers — `pkg/engine/template.go`, `pkg/engine/verify.go`
- Report formats — `pkg/report/`
- CLI flags — `cmd/w3goaudit/`

Keep `filter:` (function/contract preconditions) and `match:` (AST patterns)
cleanly separated — the loader enforces it.

## Reporting bugs

False positives / negatives: open an issue with the minimal Solidity input, the
template/command, what you expected, and what you got. For vulnerabilities in
the tool itself, see [SECURITY.md](./SECURITY.md).
