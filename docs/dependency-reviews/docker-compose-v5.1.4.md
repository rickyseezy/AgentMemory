# Docker Compose v5.1.4 dependency review

| Field | Reviewed value |
|---|---|
| Upstream | `docker/compose` |
| Release | `v5.1.4`, published 2026-05-20 |
| Annotated tag | `6ce6411902e8e3c9be91be0c572b2441486357f7` |
| Peeled commit | `4732a2ed20a49c43a7b44bb4928259162c3ae3be` |
| License | Apache-2.0 |
| Replacement | v5.1.2, which is no longer the current stable patch |
| Decision | Approved only through the signed runtime catalog and exact per-platform evidence below |

The release review used the upstream [v5.1.4 release](https://github.com/docker/compose/releases/tag/v5.1.4), not a mirror or floating latest URL. The update includes fixes after v5.1.2 for provider output/watch behavior, Docker Desktop proxy routing, and provider lifecycle handling. AgentMemory does not import Compose as an SDK: the launcher executes a separately verified, immutable binary through its closed argv/process authority.

## Approved platform artifacts

All values below are SHA-256 digests published for the exact GitHub release assets. The release verifier must additionally validate each downloaded Sigstore bundle, provenance subject, SBOM association, trusted identity, transparency proof, revocation policy, and size. A digest in this review is not a standalone execution authority.

| Platform | Executable | CycloneDX SBOM | SLSA provenance | Sigstore bundle |
|---|---|---|---|---|
| macOS ARM64 | `4cad7fc67dd089a598a15598ad38d04e6f23bf299846d26b2c572f1f96a7c49f` | `529650ca5304f90d2958e7387e3aa033fe87af99e69d7a2e528083b752c7bf38` | `983374926035c526e8dedb590b18c3cb43f47b31c39a75df8c98d61ceb662d18` | `74e37acdc74888dcb32a40887124214b9031aad86798269aa8030f96f1eb1fef` |
| macOS x86_64 | `c6f6915295918b59c2848e8978612691fdbbef05cae8cae3b78b10aec3e3dbc7` | `998f940ea6fa5121f44bf79acf9bd056b870fd1ef95aa3f0fdd710c0dabea640` | `47635f9888dad7ef8d32bb50026e8b19681a448e374b781fb0d3cee80b4ba76f` | `afff55eb9643ce421c47b10b6420e2bdbdf498adce6391d076257e54c8126309` |
| Linux ARM64 | `d4fb48b72857810314d3ee77123c89954101844efa4788031221f4c370495946` | `15864e87cf507ed17d0f5369a6165a385bb5fabc965be50b2432160220152d85` | `9ce82c257feae09d7f8e2aa60dc28df0270b8301ca55e9d47a77c6710a6737bd` | `1c7e470f992a833544ee82ba90803bc3552a2488b3ffa43138c974b1a3650548` |
| Linux x86_64 | `33b208d7e76639db742fae84b966cc01dacae58ca3fc4dabbc907045aefdf0c4` | `f26ddca002cafee7a30338b346f5005952f0f6b5587a376c10d5dd7f557c558a` | `afc2fd7d8128455bd6e99dcb9253977627a9c15862f4d9ec79f64a38a849a5df` | `3d3b02615f5e9dac2976c07e84ee41629d311a20026b5936c7ae3ba51b6f7ec7` |
| Windows x86_64 | `e1a8faff28c7433635201a2222171b727f33ecdb0ed367e54d162d00432f39aa` | `7ac0db400d81a7b4f12eb3645e521269a0b4df0c9e8f87ad0690f179568b48d9` | `9ab0631395acf789f4e9f55ac8d9fa32e02f71599180ff6eba21f8df644aa147` | `78f4179db4a5a51290fd8474bfcdd71bcff97f5a90efe4d5222bcf3879cc72cf` |

Windows ARM64 and Linux architectures outside the certified AgentMemory matrix are not approved by this review.

## Verification performed

- Resolved the signed annotated tag and peeled commit independently with Git.
- Matched every supported SBOM download to the digest returned by the upstream GitHub Releases API.
- Scanned all five supported platform SBOMs with Trivy 1.18.3 using its current vulnerability database; no fixed HIGH or CRITICAL advisory was reported. CI and release assembly must repeat the scan with the pinned current scanner/database and fail on database staleness.
- Downloaded the macOS ARM64 executable, matched its upstream digest, and executed `version --short`; it returned exactly `5.1.4`.

The Compose-render compatibility suite must run the exact reviewed binary against the locked AgentMemory Compose document on both OCI target architectures before release. A newer Compose patch requires a new review, evidence set, compatibility golden, and signed runtime-catalog sequence.
