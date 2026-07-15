#!/bin/sh
set -eu
umask 077

input=${AGENTMEMORY_UNSIGNED_NATIVE_DIR:?AGENTMEMORY_UNSIGNED_NATIVE_DIR is required}
output=${AGENTMEMORY_SIGNED_NATIVE_DIR:?AGENTMEMORY_SIGNED_NATIVE_DIR is required}
application_identity=${AGENTMEMORY_MAC_APPLICATION_IDENTITY:?AGENTMEMORY_MAC_APPLICATION_IDENTITY is required}

case "${input}:${output}" in
  *"\n"*|*"\r"*)
    echo "Native signing paths contain a line break" >&2
    exit 1
    ;;
esac

test -d "${input}"
test ! -L "${input}"
test ! -e "${output}"
output_parent=$(dirname "${output}")
test -d "${output_parent}"
test ! -L "${output_parent}"

launcher=${input}/agentmemory
helper=${input}/agentmemory-runtime-helper
for executable in "${launcher}" "${helper}"; do
  test -f "${executable}"
  test ! -L "${executable}"
done

work=$(/usr/bin/mktemp -d "${output_parent}/.agentmemory-sign.XXXXXX")
trap '/bin/rm -rf "${work}"' EXIT HUP INT TERM
/bin/cp -p "${launcher}" "${work}/agentmemory"
/bin/cp -p "${helper}" "${work}/agentmemory-runtime-helper"

/usr/bin/codesign --force --identifier com.rickyseezy.agentmemory.launcher \
  --options runtime --timestamp --sign "${application_identity}" \
  --entitlements packaging/darwin/launcher.entitlements "${work}/agentmemory"
/usr/bin/codesign --force --identifier com.rickyseezy.agentmemory.runtime-helper \
  --options runtime --timestamp --sign "${application_identity}" \
  --entitlements packaging/darwin/runtime-helper.entitlements "${work}/agentmemory-runtime-helper"

for executable in "${work}/agentmemory" "${work}/agentmemory-runtime-helper"; do
  /usr/bin/codesign --verify --strict --verbose=4 "${executable}"
done

/bin/mv "${work}" "${output}"
trap - EXIT HUP INT TERM
