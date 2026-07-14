FROM python:3.14.6-slim-bookworm@sha256:4ff4b92a68355dbdb52584ab3391dff8d371a61d4e063468bfd0130e3189c6d9 AS python-builder

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
RUN set -eu; \
    python -m pip wheel --no-deps --no-build-isolation --wheel-dir /wheelhouse /build; \
    python -m pip install --no-index --find-links=/wheelhouse --require-hashes \
      --requirement /build/locks/python-requirements.txt; \
    python -m pip install --no-index --find-links=/wheelhouse --no-deps agentmemory==0.1.0; \
    rm -rf /root/.cache

FROM ghcr.io/ggml-org/llama.cpp:server-b9982@sha256:ae4883b4bf0814bfe44cb8b4cdc5208412f61599200fb8482a96935cdacc184e AS provider

ARG VERSION=0.1.0
ARG VCS_REF=0000000000000000000000000000000000000000
ARG SOURCE_DATE_EPOCH=0
LABEL org.opencontainers.image.title="AgentMemory Local Provider" \
      org.opencontainers.image.description="Authenticated local Qwen inference sidecar" \
      org.opencontainers.image.source="https://github.com/rickyseezy/AgentMemory" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      io.agentmemory.llama-cpp.version="b9982" \
      io.agentmemory.llama-cpp.revision="99f3dc32296f825fec94f202da1e9fede1e78cf9"
ENV HOME=/nonexistent \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    LD_LIBRARY_PATH=/app:/usr/local/lib \
    PATH=/usr/local/bin:/usr/bin:/bin \
    PYTHONHASHSEED=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/tmp
COPY --from=python-builder /usr/local /usr/local
RUN set -eu; \
    test "${VERSION}" = "0.1.0"; \
    test "${VCS_REF}" != ""; \
    test "${SOURCE_DATE_EPOCH}" -ge 0; \
    /app/llama-server --version 2>&1 | grep -F "version: 9982 (99f3dc322)"; \
    install -d -o 10001 -g 10001 -m 0700 /run/agentmemory; \
    install -d -o 10001 -g 10001 -m 0750 \
      /models /models/embedding /models/reranking /models/extraction
USER 10001:10001
WORKDIR /run/agentmemory
EXPOSE 8080
ENTRYPOINT ["agentmemory-provider"]
CMD ["serve"]
HEALTHCHECK --interval=10s --timeout=5s --start-period=120s --retries=12 \
    CMD ["agentmemory-provider", "healthcheck"]
