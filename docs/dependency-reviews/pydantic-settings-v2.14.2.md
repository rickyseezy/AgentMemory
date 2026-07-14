# Dependency review: pydantic-settings 2.14.2

Status: approved for the PF-001 local Core configuration boundary on
2026-07-14.

## Identity and immutability

- Package: `pydantic-settings`
- Version: `2.14.2`, exact-pinned in `pyproject.toml` and `uv.lock`
- Registry: `https://pypi.org/simple`
- Wheel SHA-256: `a20c97b37910b6550d5ea50fbcc2d4187defe58cd57070b73863d069419c9440`
- Source distribution SHA-256: `c19dd64b19097f1de80184f0cc7b0272a13ae6e170cbf240a3e27e381ed14a5f`

`uv sync --frozen` must resolve only the reviewed lock entry. A version,
registry URL, distribution hash, dependency, or build-backend change requires
this review to be reopened.

## Approved surface and controls

The Core may use `BaseSettings` and `SettingsConfigDict` only in its outer
configuration adapter. Settings are frozen, reject unknown fields, accept only
the closed environment names and literal service identities declared by
`CoreSettings`, and contain protected-file references rather than secret
values. Domain and application packages may not import this dependency.

AgentMemory does not use `NestedSecretsSettingsSource`, does not let this
library traverse a secrets directory, and reads exact secret files through its
separate owner/mode/link-rejecting protected-file adapter. The patched version
is nevertheless mandatory so a later settings-source change cannot silently
reintroduce the known unsafe implementation.

## Security decision

GitHub advisory `GHSA-4xgf-cpjx-pc3j` affects versions `>=2.12.0,<2.14.2` and
is patched in `2.14.2`. The affected nested-secrets source could follow a
symlink outside `secrets_dir`, bypass its size accounting, read local files,
and amplify traversal through cyclic links (CWE-22, CWE-59, and CWE-400). The
reviewed advisory rates it Moderate, CVSS 5.3, and lists no known CVE:
<https://github.com/advisories/GHSA-4xgf-cpjx-pc3j>.

The earlier `2.14.1` pin is prohibited. `pip-audit --strict` remains a release
gate; any new applicable advisory blocks release until its policy decision and
fixed immutable distribution are reviewed.
