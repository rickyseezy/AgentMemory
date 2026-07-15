# Linux native package

This directory defines the Debian and RPM payload for the signed AgentMemory
launcher. It is a release-assembly input, not a substitute for the signed
runtime catalog or retained bundle.

The package installs both native binaries below `/usr/libexec/agentmemory`, a
convenience launcher symlink at `/usr/bin/agentmemory`, and one shared retained
bundle at `/usr/libexec/agentmemory/resources/bundle`. Both binaries therefore
resolve the same descriptor-rooted release authority without an environment
variable, working-directory lookup, or caller-selected path.

The Polkit action is selected only for the exact helper path and exact first
argument `--request-stdin`. Polkit does not validate the remaining arguments,
so the helper itself independently requires that this is the complete argv,
requires effective UID 0, accepts a bounded canonical request only on stdin,
and implements five closed operations. Authorization is never retained.

The package creates `/var/lib/agentmemory/runtime-helper` as root-owned state.
The helper creates its private receipt key as `0600`, its public key as `0444`,
its lock files as `0600`, and its authenticated rollback journals below that
root. Normal upgrade/removal preserves this state; only an authenticated purge
workflow may delete it.

Build the staging tree only through the production decoder-backed assembler:

```sh
go run ./apps/launcher/cmd/agentmemory-linux-release \
  -root . \
  -bundle /absolute/path/to/verified-bundle \
  -trust /absolute/path/to/native-release-trust.json \
  -output /absolute/path/to/new-stage \
  -arch amd64 \
  -source-date-epoch "$SOURCE_DATE_EPOCH"
```

The assembler requires a clean Git revision, validates the trust document with
the launcher's production decoder, rejects links and special bundle entries,
cross-builds both exact Linux entry points with the same embedded public trust,
normalizes files to `0644`, binaries/directories to `0755`, assigns every entry
the release epoch, and atomically publishes a previously nonexistent stage.

Package that stage with pinned nFPM 2.47.0. Release assembly must provide these
environment variables:

- `AGENTMEMORY_PACKAGE_ARCH`: `amd64` or `arm64`;
- `AGENTMEMORY_PACKAGE_VERSION`: numeric SemVer without a `v` prefix;
- `AGENTMEMORY_PACKAGE_RELEASE`: positive package revision;
- `AGENTMEMORY_PACKAGE_STAGE`: absolute staging directory containing the two
  root-owned binaries and a symlink-free `bundle/` tree.

Release assembly must also set `SOURCE_DATE_EPOCH` to the release commit's
Unix timestamp. nFPM uses that standard input as the package-wide modification
time when `mtime` is omitted; nFPM does not template the `mtime` field. The
assembler separately normalizes the retained bundle because nFPM `tree`
entries preserve source mtimes.

The resulting package is not publishable until the release workflow binds it
to the signed manifest, SBOM, provenance, vulnerability/license decisions,
offline Sigstore evidence, repository metadata, and the owner-supplied package
signing authority.
