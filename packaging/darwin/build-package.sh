#!/bin/sh
set -eu
umask 077

stage=${AGENTMEMORY_PACKAGE_STAGE:?AGENTMEMORY_PACKAGE_STAGE is required}
version=${AGENTMEMORY_PACKAGE_VERSION:?AGENTMEMORY_PACKAGE_VERSION is required}
architecture=${AGENTMEMORY_PACKAGE_ARCH:?AGENTMEMORY_PACKAGE_ARCH is required}
output=${AGENTMEMORY_PACKAGE_OUTPUT:?AGENTMEMORY_PACKAGE_OUTPUT is required}
installer_identity=${AGENTMEMORY_MAC_INSTALLER_IDENTITY:?AGENTMEMORY_MAC_INSTALLER_IDENTITY is required}
notary_profile=${AGENTMEMORY_MAC_NOTARY_PROFILE:?AGENTMEMORY_MAC_NOTARY_PROFILE is required}

if ! /usr/bin/printf '%s\n' "${version}" | /usr/bin/grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' ||
  test "${version}" = 0.0.0; then
  echo "Package version must be a nonzero numeric SemVer core" >&2
  exit 1
fi
case "${architecture}" in
  amd64) distribution=packaging/darwin/distribution-amd64.xml ;;
  arm64) distribution=packaging/darwin/distribution-arm64.xml ;;
  *)
    echo "Package architecture must be amd64 or arm64" >&2
    exit 1
    ;;
esac

payload=${stage}/payload
launcher=${payload}/usr/local/bin/agentmemory
helper=${payload}/Library/PrivilegedHelperTools/com.rickyseezy.agentmemory.runtime-helper
bundle=${payload}/Library/Application\ Support/AgentMemory/resources/bundle
for path in "${launcher}" "${helper}"; do
  test -f "${path}"
  test ! -L "${path}"
  /usr/bin/codesign --verify --strict --verbose=4 "${path}"
done
test -d "${bundle}"
test ! -L "${bundle}"
if /usr/bin/find "${payload}" -type l -print -quit | /usr/bin/grep -q .; then
  echo "Package payload contains a symbolic link" >&2
  exit 1
fi

test ! -e "${output}"
output_parent=$(dirname "${output}")
test -d "${output_parent}"
test ! -L "${output_parent}"
work=$(/usr/bin/mktemp -d "${output_parent}/.agentmemory-package.XXXXXX")
trap '/bin/rm -rf "${work}"' EXIT HUP INT TERM
component=${work}/agentmemory-component.pkg
package=${work}/agentmemory.pkg

/usr/bin/pkgbuild --root "${payload}" \
  --identifier com.rickyseezy.agentmemory \
  --version "${version}" \
  --install-location / \
  --scripts packaging/darwin/scripts \
  "${component}"
/usr/bin/productbuild --distribution "${distribution}" \
  --package-path "${work}" \
  --sign "${installer_identity}" \
  "${package}"
/usr/sbin/pkgutil --check-signature "${package}"
/usr/bin/xcrun notarytool submit "${package}" --keychain-profile "${notary_profile}" --wait
/usr/bin/xcrun stapler staple "${package}"
/usr/bin/xcrun stapler validate "${package}"
/usr/sbin/spctl --assess --verbose=4 --type install "${package}"

/bin/mv "${package}" "${output}"
trap - EXIT HUP INT TERM
