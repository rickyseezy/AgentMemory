# Mutmut 3.6.0 dependency review

| Field | Decision |
|---|---|
| Scope | Development/test dependency only |
| Version | Exact pin `3.6.0` in `pyproject.toml` and `uv.lock` |
| Source | PyPI release and upstream documentation |
| Python support | Declares Python 3.10–3.14 |
| License | BSD-3-Clause |
| Network/runtime impact | None in shipped AgentMemory artifacts; mutation runs are local/CI only |
| Platform constraint | Requires `fork`; the Python mutation job runs on Linux/macOS, not native Windows |
| Wheel SHA-256 | `a9f5b8dcf6cbf9496769d7cf8bdbba37a0ec709ad98f88d103238b62f10bdf37` |
| Source SHA-256 | `bcbd3e4d0d2d4edf3dfb42955417279a8866a3dbbcb87d619f2f3fd0ac7fafda` |

Mutmut is selected because Section 8.4 of the technical requirements explicitly names it for Python
mutation testing. The product-quality job mutates only the PF-002 critical domain module, runs focused
tests, and passes the generated metadata to an independent bounded parser. Mutmut's process exit code
alone is not treated as threshold evidence because a completed run may still contain surviving
mutants.

The generated `mutants/` directory is ignored and never packaged. The verifier rejects links, missing
metadata, oversized/malformed JSON, duplicate mutant identities, empty campaigns, invalid thresholds,
and scores below 80%. Updating Mutmut requires a new exact lock, review of metadata semantics and
platform support, a clean campaign, and an updated dependency review.

References: [PyPI package metadata](https://pypi.org/project/mutmut/) and
[upstream documentation](https://mutmut.readthedocs.io/).
