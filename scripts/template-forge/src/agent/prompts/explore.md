# Stage: Explore (root-cause)

Follow the methodology below to extract a precise, STRUCTURED root cause for this candidate. You
have web access — USE IT to fetch the reference links and on-chain pages before answering.

=== METHODOLOGY (finding-root-cause skill) ===
${skill}
=== END METHODOLOGY ===

## Candidate

Kind: ${kind}
Title: ${title}
Severity: ${severity}
Chain: ${chain}

Reference links (fetch these):
${links}

On-chain identifiers:
${onchain}

Existing notes / finding body:
${rootCause}

PoC / exploit code:
${poc}

Already-fetched vulnerable contract source (may be empty):
${code}

## Your task

Browse the links, read the code, and produce the `RootCause` JSON exactly as specified in the
methodology — paying special attention to `triggerConditions` (the must-have preconditions to fire
the bug), `vulnerableCode`, `fixedCode`, and the `logicBug` / `detectabilityHint` triage. Do not
fabricate; leave a field empty if sources don't support it.
