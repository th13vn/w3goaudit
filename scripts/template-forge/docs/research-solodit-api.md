# Research — Solodit API

Captured 2026-06-24. Confirm anything marked ⚠️ against the live docs before relying on it.

## What it is

Solodit (by Cyfrin) aggregates 50,000+ smart-contract security findings from top audit
firms (Cyfrin, Sherlock, Code4rena, Trail of Bits, OpenZeppelin, …). The **Solodit API**
went live Nov 2025.

## Auth

- Create an account at <https://solodit.cyfrin.io> → profile dropdown (top right) → **API Keys**.
- Key format: `sk_...`. We read it from env `CYFRIN_API_KEY`.

## Surface

The API is documented primarily as an **MCP server** exposing these tools:

- `search_vulnerabilities` — keywords, **impact severity**, audit firm, tags, protocol
  category, programming language, protocol name, min quality score, sorting, pagination.
- `get_finding` — by id or slug.
- `list_audit_firms`, `list_tags`, `list_protocol_categories`, `list_languages`,
  `get_statistics`, `clear_cache`.

## ⚠️ REST transport unknown

The public docs (<https://docs.solodit.cyfrin.io>) describe the platform + the MCP tools but
do **not** publish REST base URL / endpoint paths / rate limits at time of writing. The
pipeline therefore isolates Solodit behind `SoloditClient` (`src/sources/solodit.ts`):

- `FixtureSoloditClient` — local JSON, used now for offline runs + tests (`--fixture`).
- `RestSoloditClient` — generic REST adapter; needs `SOLODIT_API_BASE` + `CYFRIN_API_KEY`.
  Sends `Authorization: Bearer <key>`. **Confirm the base URL, the exact endpoint paths
  (`/search_vulnerabilities`, `/get_finding`), and the param names** before production use.
- MCP transport: the official MCP server is best consumed directly by opencode's MCP tools;
  the deterministic fetcher uses REST or a fixture.

## How we use it

- `fetch:findings` filters to **High + Medium** by default, paginates, and is **rate-limited**
  (`TokenBucket`, `RATE_LIMIT_RPS`, exponential backoff on HTTP 429 honoring `Retry-After`).
- Page cursor is checkpointed in `fetch_cursor` for resume.
- When a finding links a GitHub source file, `enrich/github.ts` fetches it (cached) so the
  Drafter can deep-understand the bug.

## Sources

- <https://solodit.cyfrin.io/>
- <https://docs.solodit.cyfrin.io/>
- Solodit API launch announcement (X/LinkedIn, Nov 2025).
