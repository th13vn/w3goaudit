#!/bin/sh
# Pretend opencode that returns schema-invalid JSON every time.
printf '%s' '{"bucket":"not-a-real-bucket"}' > "$FORGE_OUT"
