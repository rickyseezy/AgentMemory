FROM golang:1.26.5-bookworm@sha256:18aedc16aa19b3fd7ded7245fc14b109e054d65d22ed53c355c899582bbb2113 AS builder

ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=0.1.0
ARG VCS_REF=0000000000000000000000000000000000000000
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY apps/launcher ./apps/launcher
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags="-s -w" \
    -o /out/agentmemory-mcp-session ./apps/launcher/cmd/agentmemory-mcp-session

FROM scratch

ARG VERSION=0.1.0
ARG VCS_REF=0000000000000000000000000000000000000000
LABEL org.opencontainers.image.title="AgentMemory MCP Session" \
      org.opencontainers.image.description="Transient least-privilege AgentMemory MCP bridge" \
      org.opencontainers.image.source="https://github.com/rickyseezy/AgentMemory" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"
COPY --from=builder --chown=10001:10001 /out/agentmemory-mcp-session /usr/local/bin/agentmemory-mcp-session
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/agentmemory-mcp-session"]
