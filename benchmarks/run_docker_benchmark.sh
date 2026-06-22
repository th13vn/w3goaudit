#!/usr/bin/env bash
set -euo pipefail

# Builds a self-contained benchmark image and runs the benchmark inside it.
# The source code is copied into the image at build time; only benchmarks/results
# is mounted back to the host so the generated report is easy to read.

IMAGE="${IMAGE:-w3goaudit-benchmark:latest}"
OUT="${OUT:-benchmarks/results/latest}"
PLATFORM="${PLATFORM:-linux/amd64}"

docker build --pull --platform "${PLATFORM}" -f benchmarks/Dockerfile -t "${IMAGE}" .

mkdir -p benchmarks/results
docker run --rm --platform "${PLATFORM}" \
  -v "$(pwd)/benchmarks/results:/workspace/benchmarks/results" \
  "${IMAGE}" \
  python3 benchmarks/run_benchmark.py \
    --tools w3goaudit,slither,semgrep \
    --w3goaudit-bin /usr/local/bin/w3goaudit \
    --out "${OUT}" \
    "$@"
