#!/bin/sh
set -eu

# The helper state contains the machine receipt identity and rollback journals.
# Ordinary removal and upgrade must preserve it. An explicit product-level
# purge flow will remove it only after uninstall ownership is authenticated.
exit 0
