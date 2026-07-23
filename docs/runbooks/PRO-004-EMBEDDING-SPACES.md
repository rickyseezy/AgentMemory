# PRO-004 immutable embedding-space runbook

## Purpose

Use this runbook when creating or diagnosing the initial physical generation for one immutable
embedding space. Use the PRO-008 migration runbook for backfill, dual-write, validation, cutover,
rollback, or retirement. Never reuse or transform vectors from another space.

## Preconditions

- AgentMemory Core is Ready at relational head `0037_pro004_embedding_spaces` or a later certified
  head, and graph head `0005_pro004_embedding_space_constraints` or a later certified head.
- The provider profile is active and its current schema-v2 capability attestation matches the exact
  adapter, endpoint class, model revision/weight, configuration, dimension, dtype, normalization,
  similarity, purpose, and execution class.
- The caller holds a current Brain-wide owner or administrator grant.
- The complete descriptor contains immutable digests and revisions; aliases such as `latest`, mutable
  image tags, display names, credentials, and provider health are not descriptor coordinates.
- Neo4j has capacity for a separate generation. One semantic change always requires another index.

## Ensure a generation

Send the complete descriptor through the authenticated loopback Core API. The `Idempotency-Key` must
equal `operation_id`:

```http
POST /v1/providers/embedding-spaces/generations
Authorization: Bearer <launcher-capability>
Idempotency-Key: ensure-retrieval-document-space-001
Content-Type: application/json

{
  "operation_id": "ensure-retrieval-document-space-001",
  "brain_id": "<uuid-v7>",
  "actor_id": "<uuid-v7>",
  "grant_id": "<uuid-v7>",
  "project_id": "<uuid-v7>",
  "repository_id": "<uuid-v7>",
  "profile_id": "<uuid-v7>",
  "capability_attestation_id": "<lowercase-sha256>",
  "descriptor": {
    "adapter_id": "<registered-adapter-id>",
    "adapter_digest": "<lowercase-sha256>",
    "adapter_version": "<immutable-version>",
    "endpoint_class": "<approved-endpoint-class>",
    "model_id": "<model-id>",
    "model_revision": "<immutable-revision>",
    "model_weight_digest": null,
    "tokenizer_id": "<tokenizer-id>",
    "tokenizer_revision": "<immutable-revision>",
    "tokenizer_digest": "<lowercase-sha256>",
    "pooling": "<pooling-contract>",
    "preprocessing_version": "<pipeline-version>",
    "unicode_normalization": "NFC",
    "line_normalization": "LF",
    "chunking_contract": "<chunking-contract>",
    "truncation_policy": "reject",
    "dimension": 1024,
    "dtype": "float32",
    "vector_encoding": "float32-list",
    "normalization": "l2",
    "similarity": "cosine",
    "quantization": "none",
    "inference_settings_digest": "<lowercase-sha256>",
    "purpose": "retrieval_document",
    "asymmetry_mapping": "document-v1",
    "instruction_template_digest": "<lowercase-sha256>",
    "runtime_image_digest": "<lowercase-sha256>",
    "deterministic_inference": true,
    "execution_class": "local",
    "residency_class": "global"
  }
}
```

A successful response is `201` and state `populating`. An exact replay returns the same space and
generation. Do not infer success from an existing Neo4j index alone; SQLite is the canonical
generation authority.

## Interpret failures

| HTTP/status | Meaning | Action |
|---|---|---|
| `403 forbidden` | Capability, principal, grant, Brain, action, or role is not authorized | Restore the correct current owner/admin grant; never widen scope |
| `409 conflict` | Idempotency, immutable history, metadata, generated name, index contract, or physical graph state disagrees | Preserve evidence and compare the exact operation, descriptor fingerprint, generation, and index metadata |
| `422 validation_failed` | Request, descriptor, profile attestation, ID, digest, enum, or time is invalid/stale | Re-probe the exact profile or correct the immutable request; never edit stored rows |
| `503 dependency_unavailable` | Canonical SQLite or derived Neo4j storage is unavailable | Restore the pinned local dependency, then replay the same operation |

Responses intentionally omit raw driver errors, Cypher, provider payloads, credentials, vectors,
instructions, source content, and paths.

## Verify the physical contract

After success:

1. Confirm the SQLite operation is `complete` and the generation is `populating`.
2. Confirm the generated label is `AMVector_<generation UUID hex>` and index is
   `am_vec_<generation UUID hex>`.
3. Run `SHOW VECTOR INDEXES` through the governed diagnostic path and verify the exact label,
   `embedding` property, dimension, similarity, `vector.quantization.type = none`, and `ONLINE`.
4. Confirm the ensured/populating domain events and outbox messages exist.
5. Verify the two central audit facts remain hash-chain connected.

Do not create, rename, drop, or alter the index manually.

## Interrupted ensure recovery

- Failure before SQLite reservation commits leaves no space, generation, operation, event, outbox, or
  audit residue.
- Failure after reservation but before Neo4j verification leaves canonical state `creating`. Restore
  Neo4j and replay the same `operation_id`, request, and idempotency key.
- Failure after Neo4j creation but before SQLite completion is also recovered by exact replay. The
  provisioner verifies the existing index rather than assuming `IF NOT EXISTS` means it is compatible.
- A conflicting existing index or metadata record is quarantined operationally; do not delete it to
  make the request pass.

## Vector-write incident response

Any binding, source-content, classification, existing-vector, or cardinality conflict rolls back the
entire batch. Preserve the Brain, generation ID, space fingerprint, content-free batch digest, source
entity IDs/hashes, operation correlation, and audit/outbox evidence. Do not put vector values, source
content, instructions, credentials, prompts, or provider responses into an incident ticket.

Re-read the current canonical source and regenerate every vector under the exact active profile and
space. Never pad, truncate, project, cast, normalize, copy, or otherwise transform a vector to satisfy
the target contract.

## Escalation

Escalate immediately for:

- the same fingerprint decoding to different canonical descriptor bytes;
- provider/model drift under an allegedly current attestation;
- any non-UUID text in a generated label/index;
- an index with wrong dimension, similarity, property, label, or quantization;
- a divergent VectorRecord replay;
- an audit-chain or migration-digest failure; or
- any evidence that a vector became visible after a transaction conflict.
