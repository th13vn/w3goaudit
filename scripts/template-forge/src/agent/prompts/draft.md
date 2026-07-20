# Stage: Draft

You write **WQL templates** for w3goaudit plus the two Solidity fixtures that prove
the template is correct. Read the WQL cheatsheet before drafting.

WQL cheatsheet: ${wqlCheatsheet}

## Candidate

Title: ${title}
Severity: ${severity}
Bucket: ${bucket}
Target WQL primitive: ${targetPrimitive}
Root cause: ${rootCause}
Must-have trigger conditions (encode these in the match where possible):
- ${triggerConditions}
Vulnerable code (seed vuln.sol from this):
${code}
Fixed code (seed safe.sol from this):
${fixedCode}

## Requirements

1. **template.yaml** — a complete WQL template with a `meta` block
   (`id` in SCREAMING-KEBAB-CASE prefixed by severity e.g. `HIGH-...`, `title`,
   `severity`, `confidence`, `description`, `recommendation`) and a `query` block
   (`scope`, optional `filter`, `match`). Use ONLY the primitive(s) for the bucket.
2. **vuln.sol** — a MINIMAL, self-contained, compilable contract that exhibits the
   vulnerability and MUST make the template fire. Seed it from the real code above.
3. **safe.sol** — the SAME contract shape with the vulnerability FIXED (guard added /
   CEI applied / safe API used). The template MUST stay silent on it.

Keep fixtures small (one contract, a few functions). The two files must differ ONLY
in the vulnerable construct, so the template's precision is genuinely tested.

Output JSON: { "templateId": <meta.id>, "templateYaml": <full yaml string>,
"vulnSol": <full solidity>, "safeSol": <full solidity> }
