FROM gcc:15.2.0-bookworm@sha256:9ca91b05c7b07d2979f16413e8b2cd6ec8a7c80ffca4121ccab0aeba33f90460 AS sqlite-builder

ARG SOURCE_DATE_EPOCH=0
ADD --checksum=sha256:c917d7db16648ec95f714974ace5e5dcf46b7dc70e26600a0a102a3141125db0 \
    https://www.sqlite.org/2026/sqlite-autoconf-3530300.tar.gz /tmp/sqlite.tar.gz
COPY deploy/docker/sqlite-no-load-extension.c /tmp/sqlite-no-load-extension.c
RUN set -eu; \
    mkdir -p /tmp/sqlite /opt/sqlite/lib; \
    tar -xzf /tmp/sqlite.tar.gz -C /tmp/sqlite --strip-components=1; \
    gcc -O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
      -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_FTS5=1 \
      -DSQLITE_ENABLE_COLUMN_METADATA=1 -DSQLITE_ENABLE_MATH_FUNCTIONS=1 \
      -DSQLITE_ENABLE_RTREE=1 -DSQLITE_OMIT_LOAD_EXTENSION=1 -DSQLITE_DQS=0 \
      -I/tmp/sqlite -c /tmp/sqlite/sqlite3.c -o /tmp/sqlite3.o; \
    gcc -O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
      -I/tmp/sqlite -c /tmp/sqlite-no-load-extension.c -o /tmp/sqlite-no-load-extension.o; \
    gcc -shared -Wl,-z,relro,-z,now,-soname,libsqlite3.so.0 \
      /tmp/sqlite3.o /tmp/sqlite-no-load-extension.o -lm -lpthread -ldl \
      -o /opt/sqlite/lib/libsqlite3.so.3.53.3; \
    ln -s libsqlite3.so.3.53.3 /opt/sqlite/lib/libsqlite3.so.0; \
    ln -s libsqlite3.so.0 /opt/sqlite/lib/libsqlite3.so; \
    touch -d "@${SOURCE_DATE_EPOCH}" /opt/sqlite/lib/libsqlite3.so.3.53.3

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
    python -m pip wheel --no-deps --no-build-isolation \
      --wheel-dir /wheelhouse /build

FROM python:3.14.6-slim-bookworm@sha256:4ff4b92a68355dbdb52584ab3391dff8d371a61d4e063468bfd0130e3189c6d9 AS runtime

ARG VERSION=0.1.0
ARG VCS_REF=0000000000000000000000000000000000000000
ARG SOURCE_DATE_EPOCH=0
LABEL org.opencontainers.image.title="AgentMemory Core" \
      org.opencontainers.image.description="Local AgentMemory Core and migration runtime" \
      org.opencontainers.image.source="https://github.com/rickyseezy/AgentMemory" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      io.agentmemory.sqlite.version="3.53.3" \
      io.agentmemory.sqlite.source-sha256="c917d7db16648ec95f714974ace5e5dcf46b7dc70e26600a0a102a3141125db0"
ENV LD_LIBRARY_PATH=/usr/local/lib \
    PATH=/usr/local/bin:/usr/bin:/bin \
    PYTHONHASHSEED=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
COPY --from=sqlite-builder /opt/sqlite/lib/ /usr/local/lib/
COPY --from=python-builder /wheelhouse /wheelhouse
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
      /run/agentmemory /var/lib/agentmemory/state /var/lib/agentmemory/artifacts; \
    rm -rf /wheelhouse /tmp/python-requirements.txt /root/.cache
COPY --chown=10001:10001 migrations /opt/agentmemory/migrations
COPY deploy/scripts/verify_sqlite.py /opt/agentmemory/bin/verify-sqlite
RUN chmod 0555 /opt/agentmemory/bin/verify-sqlite; \
    python /opt/agentmemory/bin/verify-sqlite; \
    find /opt/agentmemory/migrations -type d -exec chmod 0555 '{}' +; \
    find /opt/agentmemory/migrations -type f -exec chmod 0444 '{}' +
USER 10001:10001
WORKDIR /var/lib/agentmemory

FROM runtime AS core
EXPOSE 9411
ENTRYPOINT ["agentmemory-core"]
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=6 \
    CMD ["agentmemory-healthcheck"]

FROM runtime AS migrate
ENTRYPOINT ["agentmemory-migrate"]
HEALTHCHECK NONE
