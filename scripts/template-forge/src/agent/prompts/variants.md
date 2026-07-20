# Stage: Variants (precision/recall tuning)

Generate fixtures that stress a verified template so we can tell whether it is too
niche (misses real variants → false negatives) or too generic (fires on safe code →
false positives / noise).

## template.yaml
${templateYaml}

## vuln.sol (the canonical vulnerable fixture)
${vulnSol}

## safe.sol (the canonical safe fixture)
${safeSol}

## Produce two sets

- **recall variants** (`kind: "recall"`, `expectedFire: true`): contracts that have
  the SAME vulnerability but DIFFERENT surface syntax — renamed symbols, the guard
  moved into a modifier, the unsafe call reached via an internal helper, an alternate
  call syntax, the logic split across two contracts. The template SHOULD still fire.
- **precision variants** (`kind: "precision"`, `expectedFire: false`): near-miss SAFE
  contracts that look similar but are NOT vulnerable — the guard is present, a safe
  API is used, or the dangerous ordering is corrected. The template SHOULD stay silent.

Generate ${nVariants} of each. Each variant is a complete, compilable, single-file
contract. Make them genuinely different from the canonical fixtures, not trivial
renames of each other.

Output JSON: { "variants": [ { "variantId": <short slug>, "kind": <recall|precision>,
"expectedFire": <bool>, "sol": <full solidity> }, ... ] }
