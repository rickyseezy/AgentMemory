# ADR-013: Evidence independence, learning promotion, canary, and rollback

- Status: Accepted
- Decision owners: Learning Owner and Security Owner
- Consulted owners: Governance, Evaluation, Retrieval, Product, Agent Adapters
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before promotion, risk, evaluator, canary, or controlled-surface changes
- Supersedes: None
- Related requirements: PRD Section 8; Technical Requirements Sections 4.9, 6.5, 11.11, and 14

## Context

Observed failures can produce useful lessons, but failure does not prove agent fault, successful repair
does not prove a causal explanation, and repeated model summaries are not independent evidence.
Learned behavior must never rewrite protected system surfaces or gain execution authority through
retrieval. Promotion therefore needs deterministic evidence lineage, isolated evaluation, exact
approval binding, gradual exposure, and fast rollback.

## Decision

### Learning objects and states

TaskContract, Attempt, Outcome, Mistake/LearningCandidate, CausalHypothesis, Lesson,
ProcedureRevision, EvaluationRun, PromotionDecision, Deployment, Exposure, Application, Feedback,
AdverseOutcome, and Rollback are separate canonical aggregates/events.

Candidate lifecycle is `Observed -> Diagnosing -> ReviewReady -> UnderEvaluation -> Approved ->
Deployable`, with terminal/side states `Rejected`, `Disputed`, `Merged`, and `Superseded`. Deployment is
`Approved -> Shadow -> Canary -> Active`, with `Suspended`, `RolledBack`, `Revoked`, and `Expired`.
State changes use named commands, aggregate CAS, outbox, and audit; direct status writes are prohibited.

Task outcome is evaluated only against the exact TaskContract version/hash bound to the Attempt.
Explicit user criteria remain authoritative; inferred criteria stay labeled and cannot retroactively
change an attempt.

### Detection and attribution

Failure/correction/reversion/incident/test/tool/feedback signals create one idempotent candidate keyed
by Brain, task, attempt lineage, normalized failure signature, materially different repair signature,
and detector version. Detection records observations, attribution (`agent`, `external`, `mixed`,
`unknown`), alternatives, missing evidence, scope, and risk. It never activates behavior.

Intentional probes, negative tests, cancellation, rate limits, provider/network/host failures, and
unavailable dependencies default to external/unknown unless independent evidence supports agent fault.
Agent self-report/self-critique is candidate evidence only.

### Evidence independence

Every evidence item has a root lineage ID computed from the earliest immutable event/artifact/test/
feedback/actor observation from which it derives. `EvidenceIndependencePolicyV1` groups items when any
of these match or are causally descended:

- original event/artifact/command/test/CI run/feedback/incident ID;
- model invocation ID and input evidence roots;
- adapter transcript/source digest and stable offsets;
- evaluator run derived from the same fixture/oracle; or
- human actor statement in one review action.

Summaries, recalls, embeddings, paraphrases, subagent restatements, and model critiques of one root are
one group. A model output and validation from the same model invocation/input lineage are one group.
Circular `SUPPORTED_BY` is rejected. Independence count is by root group, not document or agent count.

Hypotheses remain `suspected` until corroborated. `confirmed` requires deterministic diagnostic,
reproduction, authenticated explicit feedback, controlled comparison, or corrective intervention plus
an independent verifier. A successful repair may support usefulness but does not alone confirm cause.

### Procedure schema and controlled surfaces

Every immutable ProcedureRevision has trigger, preconditions, exclusions, ordered steps,
postconditions, mandatory verification, prohibited shortcuts, rollback/recovery, narrow Brain/project/
repository/branch/environment/tool/host/language/framework scope, risk, expiry, evidence and approval
references, canonical content hash, and supersession. Missing verification/rollback/scope proof blocks
ReviewReady. Edits create a new revision/hash.

`ControlledSurfacePolicyV1` rejects any procedure/retrieved text attempting to modify model weights,
system/developer prompts, tool permissions, approval rules, auth/privacy/retention/egress/provider
policy, adapters/evaluators/security controls, or executable repository/system code autonomously.
Procedures are structured context data. Runtime execution gateway reauthorizes every tool/action;
retrieval never grants permission.

### Evaluation isolation

An immutable EvaluationPlan binds baseline/candidate hashes, datasets/hidden holdouts, temporal split,
counterexamples/unrelated tasks, seeds, agent/model/runtime, environment, metrics/thresholds, risk,
privacy/auth/safety suites, and repetition count. Evaluation runs in a separate unprivileged sandbox
with read-only fixtures, no production credentials/Brain/network, bounded resources/time, and only
allowlisted deterministic mocks. The acting agent cannot read hidden answers/evaluator internals.

Deterministic checks run exactly; stochastic agent/model comparisons use at least five paired runs per
case unless the signed plan's power analysis requires more. Dataset assignment and baseline/candidate
order are deterministic from a hidden evaluator seed. Signed result binds per-case encrypted evidence,
aggregate metrics, environment, and artifact digests. Model narrative cannot override measured result.

Any privacy, authorization, deletion, secret, prompt-injection, controlled-surface, or other safety
regression blocks promotion regardless of productivity. No statistically/operationally meaningful
improvement, negative transfer, or holdout regression also blocks.

### Risk and promotion policy

`PromotionPolicyV1` is:

| Class | Required promotion authority |
|---|---|
| memory correction/confidence | deterministic or explicit authorized evidence; preserve history |
| advisory non-executing lesson | validated independent evidence and negative-transfer pass; policy may auto-promote narrowly |
| read-only diagnostic procedure | pre-approved policy, sandbox pass, bounded scope, owner/admin approval, canary |
| local file/code mutation | project/workspace owner approval; execution authorization every use |
| Brain-wide procedure | at least 3 independent episodes across at least 2 projects or temporal holdouts, no critical regression, installation Owner approval |
| high-risk/destructive/deployment/credential/database/billing/external communication/auth/security | two distinct authorized approvers; never auto-promote or auto-execute; fresh execution authorization |
| controlled surface | administrator configuration/release workflow only; learning promotion is prohibited |

One person/model/agent cannot satisfy two-person separation or approve its own authored high-risk
revision. Approval binding fingerprint covers exact procedure hash/version, parameters, environment,
scope, risk, expiry, evidence-group IDs/status, evaluation plan/result, evaluator set, policy version,
and approvers. Any material field/evidence/policy/expiry change invalidates it and suspends deployment.

Cross-Brain promotion is prohibited. Signed reviewed import creates new destination candidates and does
not copy active authority. Cross-agent transfer uses structured applicability, not host-name equality.

### Shadow, canary, monitoring, and rollback

Every approved version starts Shadow: selection is recorded but no context is injected. After shadow
applicability and safety pass, default Canary uses deterministic HMAC cohort assignment over procedure
revision plus eligible project/user/agent/environment, 5% cohort, and maximum 20 applications until an
explicit policy expansion. Candidate/disputed/stale/suspended/revoked procedures never enter automatic
context.

Exposure, acknowledgment, applicability, application, verification outcome, and adverse outcome are
separate immutable events. Exposure/application frequency never raises truth/efficacy without
independent outcomes. Monitoring segments efficacy and uncertainty by exact revision/scope/environment/
agent and deduplicates correlated attempts.

A verified adverse event enqueues highest-priority `SuspendProcedureCommand`, blocks new and queued
exposure/application, bumps context-cache epoch, and atomically restores the previous active pointer.
Suspension target is p95 60 seconds/max 5 minutes; rollback/cache invalidation max 5 minutes. If no safe
prior revision exists, deployment remains disabled. All adverse/rollback history is retained subject to
deletion.

## Security and privacy impact

Derived artifacts inherit maximum source classification/scope. Evaluation fixtures are encrypted and
evaluator-scoped. Repository content cannot approve or broaden itself. Explanation returns recorded
facts/policy reason codes, not hidden reasoning. A malicious model can propose candidates but cannot
validate, approve, deploy, or authorize actions by itself.

## Compatibility, migration, and rollback

Policy, evidence grouping, procedure schema, evaluation plan, and state machines are versioned.
Changing them revalidates active approvals/deployments in shadow; a stricter rule applies immediately,
while a broader rule requires new approval. Old revisions/events stay immutable. Rollback is an atomic
deployment pointer/state transition, not deletion; data deletion follows ADR-011.

## Rejected alternatives

- Learning directly from failure or self-critique: confuses correlation/attribution.
- Counting documents/agents as independent evidence: descendants inflate confidence.
- Free-form prompt lessons: not scopeable, verifiable, or rollbackable.
- Model-as-judge alone: candidate can validate itself.
- Immediate global activation: unbounded negative transfer/blast radius.
- Retrieval granting execution authority: prompt-injection/control-surface risk.
- Autonomous prompt/policy/code/weight changes: explicitly outside product safety boundary.

## Consequences

Learning advances more slowly and stores richer lineage/evaluation records. Some useful candidates stay
narrow or require review. In return, improvement is explainable, cross-agent compatible, and reversible
without becoming autonomous self-modification.

## Verification

- Labeled mistake/probe/outage corpus and detection precision/false-positive gate.
- Lineage/circular/copy/model-run/actor/evaluator independence property tests.
- Procedure schema/scope/hash/controlled-surface adversarial tests.
- Sandbox escape, hidden holdout leakage, baseline randomization, stochastic statistics, negative
  transfer, privacy/auth/safety regression tests.
- Exhaustive risk x evidence x role x approval x state decision table; no self/two-party bypass.
- Deterministic shadow/canary cohort, queued-race, adverse kill-switch, prior-missing, cache invalidation,
  and rollback SLO tests.
- Exposure/application/outcome separation and explanation completeness without hidden reasoning.
