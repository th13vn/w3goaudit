# Slither uses solc, and solc-select publishes Linux x86_64 compiler binaries.
# The helper script builds this Dockerfile with --platform linux/amd64 so the
# Solidity compiler runs on both Intel hosts and Apple Silicon Docker Desktop.
FROM golang:1.24-bookworm

ARG SOLC_VERSION=0.8.26

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_NO_CACHE_DIR=1
ENV SEMGREP_SEND_METRICS=off
ENV PATH="/opt/benchmark-venv/bin:${PATH}"

WORKDIR /workspace

# System packages only. Slither, Semgrep, and solc-select are installed through
# Python so rebuilding the image gets the newest analyzer releases from PyPI.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/benchmark-venv \
    && pip install --upgrade pip setuptools wheel \
    && pip install --upgrade slither-analyzer semgrep solc-select \
    && solc-select install "${SOLC_VERSION}" \
    && solc-select use "${SOLC_VERSION}"

# Download Go modules before copying the whole repo so Docker can cache deps
# between source-only changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o /usr/local/bin/w3goaudit ./cmd/w3goaudit \
    && slither --version \
    && semgrep --version \
    && solc --version

CMD ["python3", "benchmarks/run_benchmark.py", "--tools", "w3goaudit,slither,semgrep", "--w3goaudit-bin", "/usr/local/bin/w3goaudit", "--out", "benchmark-results/latest"]
