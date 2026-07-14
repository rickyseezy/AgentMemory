#!/bin/sh
set -eu

secret=/run/secrets/agentmemory_neo4j_password
if [ ! -f "${secret}" ] || [ -L "${secret}" ] || [ "$(wc -c < "${secret}")" -ne 32 ]; then
    exit 1
fi
case "$(stat -c '%u:%g:%a:%h' "${secret}")" in
    7474:7474:400:1|7474:7474:600:1) ;;
    *) exit 1 ;;
esac
exec /opt/java/openjdk/bin/java --enable-native-access=ALL-UNNAMED -XX:+DisableAttachMechanism \
	-cp "/opt/agentmemory/lib:/var/lib/neo4j/lib/*" \
	io.agentmemory.container.Neo4jHealthcheck
