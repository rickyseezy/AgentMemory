# Qwen default local model set

| Field | Reviewed value |
|---|---|
| Review date | 2026-07-14 |
| Embedding | `Qwen/Qwen3-Embedding-0.6B-GGUF` at `370f27d7550e0def9b39c1f16d3fbaa13aa67728` |
| Reranking source | `Qwen/Qwen3-Reranker-0.6B` at `e61197ed45024b0ed8a2d74b80b4d909f1255473` |
| Extraction | `Qwen/Qwen3-4B-GGUF` at `bc640142c66e1fdd12af0bd68f40445458f3869b` |
| Runtime/converter | llama.cpp `b9982`, commit `99f3dc32296f825fec94f202da1e9fede1e78cf9` |
| License policy | Apache-2.0 for the reviewed Qwen model repositories |

## Decision

The default offline provider set uses only immutable official Qwen source revisions. The embedding
and extraction artifacts are the official Qwen GGUF files selected in
`deploy/model-source-lock.v1.json`. The official reranker repository does not publish a GGUF file,
so release assembly converts its exact Safetensors and tokenizer inputs with the digest-pinned
llama.cpp full image. An unaffiliated community conversion is not a release input.

The reranker conversion is closed to `q8_0`, the reviewed argument vector, the reviewed converter
image, and the complete per-file source inventory. Two isolated, network-disabled conversions on
the review host produced the same 639,150,080-byte artifact with SHA-256
`7b840768f926dba9c95ef20a841a9351e525a25f09abfd8e399e8c0a5450c3b8`.

The converted artifact was then loaded by the pinned llama.cpp runtime with `--pooling rank` and
`--reranking` while the container had no network. Its live `/rerank` probe ranked the relevant
user-API/frontend statement above an unrelated graph-storage statement. This local review evidence
does not replace the release workflow's reproducibility run, model SBOM/provenance, signature, or
certified-host qualification.

## Update policy

An update requires a new dependency review and all of the following:

1. exact upstream commit and file SHA-256/size bindings;
2. license and redistribution review;
3. two isolated conversions with an identical result for converted artifacts;
4. embedding dimension, reranking order, and extraction JSON live probes;
5. egress-disabled packet-capture evidence;
6. generated CycloneDX/SPDX SBOM, SLSA provenance, release-manifest association, and signature;
7. retrieval and learning quality evaluation with no regression beyond the approved threshold.

Mutable branches, mutable model aliases, unverified mirrors, and community conversions are rejected.
