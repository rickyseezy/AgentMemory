FROM neo4j:2026.06-community@sha256:b889fd63021aea24026ba8c6829f08735c6081ae0e7ce3710d086861e35a7b7d

ARG VERSION=0.1.0
ARG VCS_REF=0000000000000000000000000000000000000000
ARG SOURCE_DATE_EPOCH=0
LABEL org.opencontainers.image.title="AgentMemory Neo4j" \
      org.opencontainers.image.description="Offline Neo4j Community graph projection" \
      org.opencontainers.image.source="https://github.com/rickyseezy/AgentMemory" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      io.agentmemory.neo4j.version="2026.06.0" \
      io.agentmemory.neo4j.telemetry="disabled"
COPY --chown=7474:7474 --chmod=0444 deploy/docker/neo4j.conf /var/lib/neo4j/conf/neo4j.conf
COPY --chown=7474:7474 --chmod=0555 deploy/docker/neo4j-entrypoint.sh \
    /opt/agentmemory/bin/neo4j-entrypoint
COPY --chown=7474:7474 --chmod=0555 deploy/docker/neo4j-healthcheck.sh \
    /opt/agentmemory/bin/neo4j-healthcheck
COPY --chown=7474:7474 --chmod=0444 deploy/docker/Neo4jSecret.java \
    deploy/docker/Neo4jInitialPassword.java deploy/docker/Neo4jHealthcheck.java /tmp/agentmemory-java/
RUN set -eu; \
    test "${VERSION}" != ""; \
    test "${VCS_REF}" != ""; \
    test "${SOURCE_DATE_EPOCH}" -ge 0; \
    install -d -o 7474 -g 7474 -m 0555 /opt/agentmemory/lib; \
    javac -cp "/var/lib/neo4j/lib/*" -d /opt/agentmemory/lib /tmp/agentmemory-java/*.java; \
    find /opt/agentmemory/lib -type f -exec chmod 0444 '{}' +; \
    rm -rf /tmp/agentmemory-java
USER 7474:7474
EXPOSE 7687
ENTRYPOINT ["tini", "-g", "--", "/opt/agentmemory/bin/neo4j-entrypoint"]
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=12 \
    CMD ["/opt/agentmemory/bin/neo4j-healthcheck"]
