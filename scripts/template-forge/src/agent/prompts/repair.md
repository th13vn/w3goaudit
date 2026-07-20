# Stage: Repair

A drafted WQL template failed a deterministic machine gate. Fix it. The machine is
the ground truth — if it says the template did not fire on vuln.sol or fired on
safe.sol or did not parse, that is a fact, not an opinion.

WQL cheatsheet: ${wqlCheatsheet}

## Current template.yaml
${templateYaml}

## vuln.sol (template MUST fire here)
${vulnSol}

## safe.sol (template MUST stay silent here)
${safeSol}

## Machine gate failure
${machineLog}

## How to fix

- **Did not fire on vuln.sol**: the match is too narrow or references a primitive
  that does not match this AST shape. Broaden the match or fix the primitive — do
  NOT weaken it into matching everything.
- **Fired on safe.sol** (false positive): the match is too broad. Tighten it (add a
  `filter` precondition, require the specific dangerous sink, use `tainted_from`).
- **Parse / placement error**: fix the YAML structure / scope per the cheatsheet.

You may edit template.yaml AND/OR the fixtures (if a fixture was wrong), but the
fixtures must remain a faithful vulnerable/safe pair for the documented bug.

Output JSON: { "templateId": <meta.id>, "templateYaml": <full yaml>,
"vulnSol": <full solidity>, "safeSol": <full solidity> }
