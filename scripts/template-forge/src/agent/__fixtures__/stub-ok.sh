#!/bin/sh
# Pretend opencode: write a valid classification JSON to the result path.
printf '%s' '{"bucket":"taint","targetPrimitive":"args+tainted_from","rationale":"user input reaches call target"}' > "$FORGE_OUT"
