# ADR-012: Retrieval fusion, traversal/context budgets, and explanation traces

- Status: Accepted
- Decision owners: Retrieval Owner and Product Intelligence Owner
- Consulted owners: Governance, Graph, Providers, Agent Adapters, Evaluation
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before fusion weights, evidence policy, or default budgets change
- Supersedes: None
- Related requirements: PRD Section 12; Technical Requirements Sections 4.6, 7.2, 11.9, and 14

## Context

Exact identifiers, lexical search, vector spaces, graph paths, temporal state, and rerankers emit
incompatible scores. Retrieval must authorize before search, stay below local latency/context limits,
explain every result, surface partial failure, and abstain rather than turn rank into factual authority.

## Decision

### Versioned policy and pipeline

Initial policy is `retrieval-v1`. `RecallQueryHandler` performs:

1. authenticate and resolve immutable authorized Brain/project/repository/checkout/branch/commit/time
   context;
2. deterministic query analysis for exact IDs/symbols/paths/endpoints/aliases and intent;
3. parallel exact, lexical, and each applicable embedding-generation lookup under independent budgets;
4. temporal/status/classification filtering inside each store;
5. rank fusion of authorized lists;
6. bounded graph expansion around high-value fused entities;
7. optional bounded reranking of existing candidates only;
8. evidence/currentness/scope/diversity/context-budget selection;
9. support/contradiction policy and response assembly; and
10. immutable explanation-trace commit.

Authorization occurs before cache/candidate access and at every graph/evidence expansion. Query analysis
may infer search intent but never Brain/scope/authority.

### Deadlines and candidate bounds

Warm interactive recall deadline is 2 seconds. Default component budgets, all bounded by caller
deadline, are exact 500 ms, lexical 750 ms, each vector fan-out group 900 ms, graph expansion 250 ms,
and optional rerank 400 ms. Work is cancelled when its budget expires. Candidate cap is 50 per exact/
lexical/graph channel and per applicable vector generation before fusion; deduped rerank input is top
30; final default is 12.

Concurrency and total candidate bytes are bounded by the reference resource profile. When applicable
space count cannot run within the declared budget, deterministic provider-route priority selects the
eligible set and `DegradationSummary` reports omitted/timed-out generations; no hidden success is
claimed. Failure of one noncanonical channel does not fail healthy channels. Authorization/canonical
integrity failure fails the query.

Graph defaults are depth 3, maximum 500 unique nodes, 1,000 edges, 50 paths, and 250 ms. Every hop uses
predicate allowlist, Brain/narrower scope, classification, status, valid/recorded interval, branch/
commit reachability, and active assertion evidence. Cycles and repeated nodes consume budget. An
explicit graph tool may request a validated bounded override; ordinary recall never does.

### Weighted reciprocal-rank fusion

Raw lexical/vector/reranker/provider scores are retained for within-channel explanation only and never
compared across channels/spaces. For each deduplicated entity:

`base = sum(channel_weight / (60 + rank))` using one-based rank.

Initial weights are exact 1.35, lexical 1.00, graph-seed 1.10, and vector 1.00 total. When more than one
vector generation contributes, the vector weight is divided equally among applicable generation lists
so merely adding providers cannot dominate results. A candidate retains every contributing list/rank/
generation/evidence.

After fusion, bounded multipliers apply in this order: active authoritative evidence up to +15%,
current project/repository/checkout proximity up to +10%, temporal freshness/current-validity up to
+5%, and explicit authorized pin/feedback up to +5%. No boost can make an unauthorized, invalid,
deleted, unsupported, or contradicted candidate authoritative. Ties use stable entity UUID bytes.

Reranker receives only the top 30 authorized minimal candidate representations, cannot add/remove
evidence or introduce an entity, and may reorder within that set. Its normalized order is combined as
one additional rank list of weight 1.00; unavailable reranking leaves fused order and reports fallback.

### Context budgets and progressive disclosure

Every query has `ContextBudget(max_tokens, max_items, max_bytes, disclosure)`. Boundary defaults are:

- session brief: 1,200 tokens, 12 items, 20 KiB;
- standard recall: 1,500 tokens, 12 items, 24 KiB;
- timeline/subgraph/full evidence: caller must provide a bounded budget; server maxima remain enforced.

Brief is default. Items are atomic semantic units and are never cut mid-item. Allocation priority is
safety/constraints, unresolved work, decisions, failures, changes, then supporting episodes. Selection
deduplicates by entity/revision/content, enforces category/project diversity, and prevents one session
or project from consuming more than 50% unless fewer eligible alternatives exist. Full source content
is lazy and reauthorized. Conservative token counter wins when host tokenizer is unavailable.

### Support, contradiction, and abstention

Rank is relevance, not truth. `Certain` requires an active authoritative assertion or explicit
authorized user statement, accessible current evidence for the requested scope/time, no unresolved
decisive contradiction, and predicate-specific support policy. Candidate/inferred/stale/history-only
facts are `Qualified` with exact limitation. If no result meets support or contradictory evidence
cannot be resolved, response is `Unknown` plus authorized candidates/evidence where useful. Model-only
statements cannot satisfy support.

### Explanation trace

Each recall stores for 24 hours by default (or shorter deletion/retention policy) a content-minimized
trace: trace/query/scope hashes, principal/grant/policy/security epochs, temporal context, channel
deadlines/outcomes/watermarks, candidate entity IDs and per-list ranks, fusion/boost/rerank policy
versions, generation IDs, graph assertion path IDs, selected item IDs/budgets, degradation, and support
decision codes. It stores no raw query, source content, prompt, vector, or hidden reasoning unless the
authorized canonical request already requires an encrypted reference.

`ExplainRecallQuery` reauthorizes every entity/evidence at read time. Revoked/deleted evidence is shown
as unavailable, not copied from trace. Explanation reports identity/status/scope/time, why matched,
rank components, embedding generation, complete graph path/assertion per hop, support/contradiction,
freshness, and degradation.

### Context safety

Rendered memories/code/documents are typed, escaped untrusted-data sections with source/classification.
They cannot alter prompts, tools, permissions, policy, or execution. Final DLP scanner blocks/redacts
high-confidence secrets and records a content-free reason. Output contains no credential/raw secret.

## Security and privacy impact

Pre-search authorization prevents candidate/count/timing leakage; traces hash sensitive query/scope
data and expire. Lazy evidence reauthorization handles revocation/deletion. Rerank/provider payload is
minimal and governed by ADR-008. Stored injection remains data.

## Compatibility, migration, and rollback

Fusion weights, boosts, budgets, support rules, and trace schema are versioned. A policy change is
evaluated against golden/adversarial corpora and runs shadow comparison before activation. Old traces
retain their policy version. Rollback atomically selects the prior policy and invalidates retrieval
caches; it never rewrites prior trace outcomes.

## Rejected alternatives

- Comparing raw scores: scales differ across lexical/vector/providers.
- One combined vector index: violates ADR-007 space identity.
- Graph expansion before authorization or post-filtering: leaks paths/candidates.
- Reranker adding candidates: grants an external model retrieval authority.
- Unbounded graph/context or string truncation: resource and semantic corruption risk.
- Rank/confidence threshold alone as truth: ignores evidence and contradiction.
- Explanation generated from model reasoning: unreproducible and may expose hidden reasoning.

## Consequences

Fusion has fixed initial calibration and must be reevaluated before changes. Explanation storage adds
metadata, and strict budgets sometimes return Unknown/partial. Results remain deterministic,
reproducible, and safe across multiple providers.

## Verification

- Golden/permutation/property tests for RRF, vector-weight division, ties, boosts, duplicates, and raw-
  score scale attacks.
- Deadline/cancellation/outage matrix and p95 2-second reference benchmark.
- Graph cycle/scope/time/branch/denied-intermediate/budget tests.
- Token/item/byte budget properties, atomic truncation, disclosure monotonicity, and diversity tests.
- Certain/Qualified/Unknown evidence/contradiction/no-answer decision corpus.
- Trace replay/explanation/citation/path correctness with deleted/revoked evidence.
- Stored-injection/delimiter/DLP/provider payload/privacy/cardinality tests.
