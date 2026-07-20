# Exact Node 20 Bookworm base used by the benchmark image.
FROM node:20.20.2-bookworm-slim

ARG GO_LINUX_AMD64_SHA256=5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053
ARG SOLC_VERSION=0.8.26
ARG SOLC_SELECT_VERSION=1.2.0
ARG SLITHER_VERSION=0.11.5
ARG SEMGREP_VERSION=1.169.0
ARG YARN_VERSION=1.22.22
ARG FOURNALY3ER_REF=8a9d1ebb7d362bc94f036fa9123d0977c6cb7436
ARG FOURNALY3ER_LOCK_SHA256=5384b83d119c9776fee287b52965b7035de05e27d90758dedace01692f8e81cb

ENV DEBIAN_FRONTEND=noninteractive \
    GOTOOLCHAIN=local \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    SEMGREP_SEND_METRICS=off \
    VIRTUAL_ENV=/opt/benchmark-venv \
    PATH=/usr/local/go/bin:/opt/benchmark-venv/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

# The Go release is derived from the authoritative go.mod rather than repeated
# as an image argument. The pinned digest makes the toolchain download fail
# closed if either go.mod or the upstream archive changes unexpectedly.
COPY go.mod /tmp/w3goaudit-go.mod
RUN set -eux; \
    go_version="$(awk '$1 == "go" { print $2; exit }' /tmp/w3goaudit-go.mod)"; \
    test -n "${go_version}"; \
    archive="go${go_version}.linux-amd64.tar.gz"; \
    curl -fsSLo "/tmp/${archive}" "https://go.dev/dl/${archive}"; \
    echo "${GO_LINUX_AMD64_SHA256}  /tmp/${archive}" | sha256sum -c -; \
    tar -C /usr/local -xzf "/tmp/${archive}"; \
    rm "/tmp/${archive}"; \
    test "$(go version)" = "go version go${go_version} linux/amd64"

RUN python3 -m venv /opt/benchmark-venv \
    && pip install \
        "semgrep==${SEMGREP_VERSION}" \
        "slither-analyzer==${SLITHER_VERSION}" \
        "solc-select==${SOLC_SELECT_VERSION}" \
    && solc-select install "${SOLC_VERSION}" \
    && solc-select use "${SOLC_VERSION}"

# The pinned upstream commit has package.json entries absent from its checked-in
# lockfile. Resolve that incomplete lock once, verify the reviewed generated
# lock hash, then prove the completed lock supports an offline frozen install.
# Direct docker builds may override the hash, but the reviewed value is the
# authoritative default used by the canonical Compose workflow.
RUN test -n "${FOURNALY3ER_LOCK_SHA256}" \
    && test "$(yarn --version)" = "${YARN_VERSION}" \
    && git init /opt/4naly3er \
    && git -C /opt/4naly3er remote add origin https://github.com/Picodes/4naly3er.git \
    && git -C /opt/4naly3er fetch --depth 1 origin "${FOURNALY3ER_REF}" \
    && git -C /opt/4naly3er checkout --detach FETCH_HEAD \
    && test "$(git -C /opt/4naly3er rev-parse HEAD)" = "${FOURNALY3ER_REF}" \
    && yarn --cwd /opt/4naly3er install --non-interactive --ignore-scripts \
    && echo "${FOURNALY3ER_LOCK_SHA256}  /opt/4naly3er/yarn.lock" | sha256sum -c - \
    && yarn --cwd /opt/4naly3er install --offline --frozen-lockfile --non-interactive --ignore-scripts \
    && rm -rf /opt/4naly3er/.git

# Cache Go modules separately from repository source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY scripts/benchmark/4naly3er-wrapper.sh /usr/local/bin/4naly3er
COPY scripts/benchmark/entrypoint.sh /usr/local/bin/benchmark-entrypoint

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -trimpath -o /usr/local/bin/w3goaudit ./cmd/w3goaudit \
    && chmod 0755 /usr/local/bin/4naly3er /usr/local/bin/benchmark-entrypoint \
    && go_version="$(awk '$1 == "go" { print $2; exit }' go.mod)" \
    && test "$(go version)" = "go version go${go_version} linux/amd64" \
    && w3goaudit version \
    && solc --version | grep -F "${SOLC_VERSION}" \
    && slither --version | grep -F "${SLITHER_VERSION}" \
    && semgrep --version | grep -F "${SEMGREP_VERSION}" \
    && 4naly3er --version | grep -F "${FOURNALY3ER_REF}" \
    && yarn --version | grep -Fx "${YARN_VERSION}"

ENV HOME=/tmp/home \
    XDG_CACHE_HOME=/tmp/cache \
    W3GOAUDIT_BENCHMARK_CONTAINER=1

ENTRYPOINT ["/usr/local/bin/benchmark-entrypoint"]
