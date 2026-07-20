# Dependency review: cryptography 49.0.0

| Field | Decision |
|---|---|
| Package | `cryptography==49.0.0` |
| Scope | Core and host-spool AES-256-GCM authenticated encryption |
| Decision | Approved and exact-pinned |
| Reviewed | 2026-07-20 |
| Owners | Security and Persistence |

AgentMemory uses the Python Cryptographic Authority's reviewed `AESGCM` implementation rather than
implementing a primitive. The official authenticated-encryption contract accepts 256-bit AES keys,
uses a unique nonce for each encryption, authenticates associated data, and emits/verifies the full
128-bit GCM tag. AgentMemory supplies random 96-bit nonces, random 256-bit per-event DEKs, a random
256-bit per-Brain BKEK, and purpose/version/scope-bound canonical AAD as required by ADR-010.

Version 49.0.0 was released on 2026-06-12 and publishes CPython 3.14 wheels for the supported release
platforms. The project is maintained by the Python Cryptographic Authority and is classified
production/stable. Review sources:

- <https://cryptography.io/en/stable/hazmat/primitives/aead/>
- <https://pypi.org/project/cryptography/49.0.0/>

The package may be used only behind the ingestion encryption adapters. Domain/application code never
imports it. Nonce reuse, custom algorithms, shortened tags, installation-key data encryption, silent
algorithm fallback, plaintext keys in SQLite/logs, or swallowing authentication failure are forbidden.
Updates require lock regeneration, vulnerability audit, tamper/known-answer tests, supported-wheel
verification, and Security Owner review.
