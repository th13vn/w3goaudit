# AI Report Drafting Design

Date: 2026-07-01
Status: Approved design draft
Location: `.vscode/ai-designs/2026-07-01-ai-report-drafting-design.md`

## Context

`w3goaudit` is a Go CLI and SDK for Solidity static analysis. Its canonical
pipeline is `Reader -> Builder -> Database -> Engine -> Report`. A normal scan
writes a result folder with human reports, SARIF, a machine-readable corpus, and
per-main-contract workflow/state artifacts. The current codebase already has
LLM-friendly context surfaces, especially `extract bundle`, per-entry workflow
files, reachability-aware findings, related matched sites, and corpus JSON.

The AI integration should use those existing artifacts instead of changing the
WQL engine. The first useful AI feature is report drafting: turn existing static
findings and bounded source evidence into human-editable audit-report sections.

## Goal

Add an optional post-scan AI report-drafting workflow that reads an existing
w3goaudit result folder, sends finding-scoped evidence to OpenAI, and writes a
Markdown draft report for auditor review.

The MVP should preserve these properties:

- Normal `w3goaudit <path>` scans remain deterministic and do not depend on AI.
- AI output is written as a separate artifact, not merged into core scan output.
- Source sent to OpenAI is bounded to finding-scoped snippets and related context.
- Every generated draft states what evidence was used and what still needs human
  verification.

## Non-Goals

- Do not add inline AI execution to the default scan path for the MVP.
- Do not make AI the source of truth for whether a WQL finding is valid.
- Do not upload the full repository, full result folder, or full `database.json`
  by default.
- Do not design template generation, autonomous auditing, or chat-style project
  Q&A in this first spec.
- Do not introduce provider abstraction before there is a second concrete
  provider requirement.

## Recommended Approach

Use a result-folder post-processor command:

```bash
w3goaudit ai draft <result-folder>
```

This command reads the existing result artifacts and writes a new Markdown file,
for example:

```text
<result-folder>/ai-report-drafts.md
```

This approach is preferred because it keeps the static analyzer reliable and
re-runnable, avoids reparsing Solidity, gives clear privacy and token boundaries,
and fits the current result-folder architecture.

## Alternatives Considered

### Extract-Based Single-Finding Drafting

Extend the existing `extract` style with a command that drafts one selected
finding or function at a time from `--db` plus a finding/template identifier.
This is highly controllable and cheap, but it is less useful for normal audit
workflow because users must manually select findings and iterate one by one.

### Inline Scan Flag

Add a flag such as `w3goaudit <path> --ai-draft-report`. This is convenient, but
it couples scan success to API keys, network latency, provider failures, and token
cost. That would make the core rule-based scanner less predictable.

## Command UX

MVP command:

```bash
w3goaudit ai draft <result-folder> [flags]
```

Initial flags:

- `--model <name>`: OpenAI model name. Defaults to `gpt-4.1-mini` unless a
  later project config setting overrides it.
- `-o, --output <file>`: output Markdown path. Defaults to
  `<result-folder>/ai-report-drafts.md`.
- `--max-findings <n>`: cap the number of selected finding groups.
- `--template-id <glob>`: draft only matching template IDs.
- `--min-severity <severity>`: draft findings at or above a severity threshold.
- `--dry-run`: show selected finding groups and evidence sizes without API calls.

The provider is OpenAI for the MVP. The API key should come from environment or
config, not from command-line arguments, to avoid leaking secrets through shell
history.

## Architecture

Add the AI drafting feature beside the existing CLI/report pipeline, not inside
`pkg/engine`. The engine should continue to produce deterministic static
findings. AI code consumes serialized result artifacts.

Proposed components:

### `cmd/w3goaudit/ai.go`

Defines the `ai` command group and `ai draft` subcommand. Responsibilities:

- Parse flags and command arguments.
- Resolve and validate the result folder path.
- Load configuration needed for OpenAI.
- Call the drafting orchestrator.
- Print concise progress and final output path.

### `pkg/aidraft`

Owns the report-drafting workflow. The package name should stay specific to
avoid implying broad AI-agent functionality. Responsibilities:

- Load result-folder artifacts.
- Select finding groups.
- Build evidence packets.
- Call OpenAI.
- Render the final Markdown report.

### `ResultLoader`

Reads scan artifacts from the result folder:

- `corpus/findings.json` for structured findings.
- `corpus/database.json` for source lookup and contract/function metadata.
- `corpus/overview.json` when available for scan metadata.
- `<MainContract>/state-changes.md` and workflow files when they match the
  selected finding context.

It should fail with actionable messages when the folder is not a valid
w3goaudit result folder or when required corpus files are missing or malformed.

### `FindingSelector`

Groups and filters findings. Selection should mirror report behavior by grouping
on template ID and severity. Filtering uses severity threshold, template ID glob,
and max group count.

### `EvidenceBuilder`

Builds a bounded evidence packet for each selected finding group. It should use
structured JSON fields first and avoid scraping `findings.md` unless there is no
structured alternative.

Evidence packet contents:

- Template ID, title, severity, confidence, message, recommendation, and fix.
- Finding locations.
- Reachability path and entry point when present.
- Primary AST details when present.
- Related matched sites when present.
- Source excerpts for matched or related locations.
- Relevant workflow/state snippets only when they match the finding's contract or
  function.

The builder should cap source and workflow context per finding group. If context
is truncated, the draft must include a warning.

### `OpenAIClient`

Concrete OpenAI client for the MVP. Responsibilities:

- Build the request payload.
- Enforce timeout and basic retry policy.
- Use low temperature for stable report drafting.
- Return clear typed errors for missing API key, API failure, timeout, invalid
  response, and rate limit.

The code should still be testable without network calls by allowing the
orchestrator to accept a fake client in tests.

### `DraftRenderer`

Writes the final Markdown artifact. It should not overwrite core scan files.

Report layout:

```markdown
# AI Report Drafts

## Run Metadata

## Draft Warnings

## Findings

### <Severity> - <Title>

#### Draft

#### Evidence Used

#### Confidence And Caveats
```

## Data Flow

```text
result folder
  -> load corpus JSON and optional workflow/state files
  -> validate result-folder shape
  -> select finding groups
  -> build bounded evidence packets
  -> call OpenAI once per selected group
  -> validate AI response
  -> render ai-report-drafts.md
```

The pipeline is deterministic until the OpenAI call. The output should record
model name, timestamp, selected finding count, successful draft count, failed
draft count, and evidence-truncation warnings.

## Prompt Contract

Prompts should be structured and evidence-based. Each request should include a
system instruction and a user payload with explicit evidence IDs. The model must
draft only from provided evidence.

Required model behavior:

- Do not claim facts that are not supported by evidence.
- Say `Insufficient evidence` when the provided context cannot support a report
  section.
- Prefer precise Solidity/security language over generic vulnerability text.
- Cite evidence IDs for important claims.
- Preserve detector severity as input context; do not silently override it.
- Produce Markdown in the requested section order.

Requested draft sections:

- `Title`
- `Summary`
- `Root Cause`
- `Attack Path`
- `Impact`
- `Recommendation`
- `Evidence Used`
- `Confidence And Caveats`

## Error Handling

Preflight errors should stop before API calls:

- Missing OpenAI API key.
- Invalid result folder.
- Missing `corpus/findings.json` or `corpus/database.json`.
- Unparseable corpus files.
- Invalid severity or template filter flags.

Per-finding drafting errors should not discard successful drafts. By default, the
command should continue, write all successful drafts, add failed groups to `Draft
Warnings`, and return non-zero only when every selected group fails.

`--dry-run` must perform no API call. It should show selected finding groups and
evidence sizes so the user can estimate privacy and cost before drafting.

## Privacy And Safety

The MVP sends finding-scoped evidence only. It must not upload the full project,
full result folder, or complete database JSON by default.

Output should include a clear notice:

```text
This file was drafted by AI from bounded w3goaudit evidence. Treat it as a
starting point for human review, not as a final audit finding.
```

The command should warn before sending source snippets to OpenAI unless the
project later gains a config setting that records consent. The MVP can keep this
warning in command output and the generated artifact rather than introducing a
new consent system.

## Testing Strategy

No test should require a live OpenAI call. Tests should inject a fake client into
the drafting orchestrator.

Coverage areas:

- Result-folder validation for valid and malformed folders.
- Finding filtering by severity, template ID, and max group count.
- Evidence packet construction from structured findings/database data.
- Evidence-size truncation and warning propagation.
- Markdown rendering with successful drafts, partial failures, and no findings.
- CLI dry-run behavior with no client call.
- Prompt construction that includes finding-scoped evidence and does not include
  full `database.json` dumps.

Golden-file tests are appropriate for `ai-report-drafts.md` because users should
be able to diff the generated artifact across runs.

## Acceptance Criteria

- `w3goaudit ai draft <result-folder>` writes a Markdown draft report for the
  selected finding groups.
- `--dry-run` performs no API call and reports selected groups/evidence sizes.
- Missing API key fails before constructing or sending large evidence payloads.
- Invalid result folders produce actionable errors.
- OpenAI failures are visible in `Draft Warnings` when other groups succeed.
- Generated drafts include evidence used and confidence/caveat sections.
- Normal `w3goaudit <path>` scan behavior is unchanged.

## Implementation Notes

- Read package `INDEX.md` files before touching implementation packages.
- If adding `pkg/aidraft`, create or update a local `INDEX.md` for that package.
- Update root `INDEX.md`, `README.md`, and `docs/usage.md` when the command is
  implemented.
- Keep OpenAI-specific code contained so a future provider abstraction can be
  added without changing evidence construction or rendering.
- Avoid adding broad backward-compatibility layers in the MVP because there are
  no existing AI command consumers.
