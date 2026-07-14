#!/bin/sh
set -eu

secret=/run/secrets/agentmemory_neo4j_password
if [ "$(id -u)" != 7474 ] || [ "$(id -g)" != 7474 ]; then
    echo "Neo4j must run as its fixed non-root identity" >&2
    exit 1
fi
if [ ! -f "${secret}" ] || [ -L "${secret}" ] || [ "$(wc -c < "${secret}")" -ne 32 ]; then
    echo "Neo4j password secret is unavailable or invalid" >&2
    exit 1
fi
case "$(stat -c '%u:%g:%a:%h' "${secret}")" in
    7474:7474:400:1|7474:7474:600:1) ;;
    *)
        echo "Neo4j password secret ownership is unsafe" >&2
        exit 1
        ;;
esac
if [ ! -f /data/dbms/auth.ini ]; then
	/opt/java/openjdk/bin/java --enable-native-access=ALL-UNNAMED -XX:+DisableAttachMechanism \
		-cp "/opt/agentmemory/lib:/var/lib/neo4j/lib/*" \
		io.agentmemory.container.Neo4jInitialPassword
fi
exec /var/lib/neo4j/bin/neo4j console
