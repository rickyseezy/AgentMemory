FROM golang:1.26.5-bookworm@sha256:18aedc16aa19b3fd7ded7245fc14b109e054d65d22ed53c355c899582bbb2113 AS builder

ARG TARGETOS
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY apps/launcher/internal/domain/composeplan ./apps/launcher/internal/domain/composeplan
COPY apps/launcher/internal/secretprojector ./apps/launcher/internal/secretprojector
COPY apps/launcher/cmd/agentmemory-secret-projector ./apps/launcher/cmd/agentmemory-secret-projector
RUN set -eu; \
    test "${TARGETOS}" = "linux"; \
    test "${TARGETARCH}" = "amd64" -o "${TARGETARCH}" = "arm64"; \
    test "${SOURCE_DATE_EPOCH}" -ge 0; \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
      go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
      -o /out/agentmemory-secret-projector \
      ./apps/launcher/cmd/agentmemory-secret-projector

FROM scratch AS secret-projector
ARG VERSION=0.1.0
ARG VCS_REF=0000000000000000000000000000000000000000
LABEL org.opencontainers.image.title="AgentMemory Secret Projector" \
      org.opencontainers.image.description="Fail-closed protected-file volume projector" \
      org.opencontainers.image.source="https://github.com/rickyseezy/AgentMemory" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"
COPY --from=builder --chmod=0555 /out/agentmemory-secret-projector /agentmemory-secret-projector
USER 0:0
WORKDIR /
ENTRYPOINT ["/agentmemory-secret-projector"]
