# Stage: Verify (right-reason)

A template passed the TEST and REGRESSION gates. Confirm it fires for the
**documented vulnerability mechanism**, not by coincidence. The gates prove it
fires on vuln.sol and is silent on safe.sol; your job is to catch templates that
pass for the WRONG reason (e.g. matching an incidental call that happens to be
present, rather than the actual unsafe pattern).

## Original finding / incident
Title: ${title}
Root cause: ${rootCause}

## template.yaml
${templateYaml}

## vuln.sol
${vulnSol}

## Questions

1. Does the template's `match` correspond to the actual root cause described above?
2. Would it fire on a DIFFERENT contract that has the same root cause but different
   surface syntax? (If not, it is too niche — flag it.)
3. Would it plausibly fire on benign contracts that merely use a similar API? (If so,
   it is too generic — flag it.)

Output JSON: { "rightReason": <true|false>, "rationale": <2-4 sentences>,
"confidence": <LOW|MEDIUM|HIGH> }
