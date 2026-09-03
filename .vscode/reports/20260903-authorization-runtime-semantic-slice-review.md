# Authorization and Runtime-Inheritance Semantic Slice Review

## Delivered

- Versioned `AuthorizationFacts` v1.0.0 in `pkg/types` with exact IDs, deterministic normalization, detached snapshots, bounded queries (max 200), and explicit legacy-cache unavailability.
- Builder phase after effects indexes function authorization evidence, principal kind, dominance, unresolved modifiers, self-scoping, initializer mutex, constructor disable pattern, and first-call takeover uncertainty.
- Runtime/entry reachability records now carry additive `authVerdict` and `authReasons`; `EntryPoint` mirrors the first hop evidence.
- WQL catalog accepts `auth_verdict`, `auth_principal`, `auth_dominates`, `runtime_contract`, and `auth_reason`; matching is fail-closed when facts are absent or unknown.
- Result bundles emit `data/authorization.json` and index it in `data/manifest.json`.
- Candidate templates are isolated under `templates/candidate/authorization/` and strict-load successfully. Official templates were not modified.

## Verification

- `go test ./...` passes.
- Touched-package race tests pass for `pkg/types`, `pkg/builder`, `pkg/engine`, and `pkg/report`.
- `git diff --check origin/main...HEAD` passes.
- Candidate pack loader returns all three candidates without validation errors.
- Official template tree remains unchanged by the slice.

## Limitations and next gate

This is the first deterministic vertical slice, not a release claim. Expected-principal callback identity remains conservative and must be expanded with exact pool/manager provenance fixtures. Proxy deployment linkage and atomic initialization remain `unknown` unless statically proven. No official template promotion, tag, push, release, or external AI Assistant work is performed.
