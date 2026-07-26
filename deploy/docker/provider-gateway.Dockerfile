FROM python:3.14.6-slim-bookworm@sha256:4ff4b92a68355dbdb52584ab3391dff8d371a61d4e063468bfd0130e3189c6d9 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
COPY deploy/locks/python-build-requirements.txt deploy/locks/python-requirements.txt /build/locks/
RUN set -eu; \
    python -m pip download --require-hashes --only-binary=:all: \
      --dest /wheelhouse --requirement /build/locks/python-requirements.txt; \
    python -m pip install --require-hashes \
      --requirement /build/locks/python-build-requirements.txt
COPY pyproject.toml README.md /build/
COPY src /build/src
RUN python -m pip wheel --no-deps --no-build-isolation --wheel-dir /wheelhouse /build

FROM python:3.14.6-slim-bookworm@sha256:4ff4b92a68355dbdb52584ab3391dff8d371a61d4e063468bfd0130e3189c6d9 AS gateway

ARG VERSION=0.1.0
ARG VCS_REF=0000000000000000000000000000000000000000
ARG SOURCE_DATE_EPOCH=0
LABEL org.opencontainers.image.title="AgentMemory Provider Gateway" \
      org.opencontainers.image.description="Isolated authenticated provider egress gateway" \
      org.opencontainers.image.source="https://github.com/rickyseezy/AgentMemory" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"
ENV HOME=/nonexistent \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/usr/local/bin:/usr/bin:/bin \
    PYTHONHASHSEED=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/tmp
COPY --from=builder /wheelhouse /wheelhouse
COPY deploy/locks/python-requirements.txt /tmp/python-requirements.txt
RUN set -eu; \
    test "${VERSION}" != ""; \
    test "${VCS_REF}" != ""; \
    test "${SOURCE_DATE_EPOCH}" -ge 0; \
    python -m pip install --no-index --find-links=/wheelhouse --require-hashes \
      --requirement /tmp/python-requirements.txt; \
    python -m pip install --no-index --find-links=/wheelhouse --no-deps \
      "agentmemory==${VERSION}"; \
    install -d -o 10001 -g 10001 -m 0700 \
      /run/agentmemory /var/lib/agentmemory/telemetry; \
    rm -rf /wheelhouse /tmp/python-requirements.txt /root/.cache
USER 10001:10001
WORKDIR /run/agentmemory
EXPOSE 8080
ENTRYPOINT ["agentmemory-provider-gateway"]
CMD ["serve"]
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=6 \
    CMD ["agentmemory-provider-gateway", "healthcheck"]
