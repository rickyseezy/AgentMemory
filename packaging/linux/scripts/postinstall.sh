#!/bin/sh
set -eu

if command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --create agentmemory-runtime-helper.conf
else
  install -d -m 0755 -o root -g root /var/lib/agentmemory
  install -d -m 0755 -o root -g root /var/lib/agentmemory/runtime-helper
fi

exit 0
