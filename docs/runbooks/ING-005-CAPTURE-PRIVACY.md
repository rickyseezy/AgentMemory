# ING-005 capture privacy runbook

Use this runbook when an event is reported as `ignored`, a capture is rejected as malformed or unsafe,
content is unexpectedly classified `restricted`/`local_only`, or a provider operation is denied. Do
not edit policy rows, privacy decisions, encrypted envelopes, or digests manually.

## Interpret terminal outcomes

- `accepted` means the sanitized or encrypted local-only event and its privacy receipt committed with
  the outbox and append audit.
- `duplicate` means the exact immutable event already exists; no second durable side effect occurred.
- `ignored` means policy excluded the content before canonical event persistence. This is a terminal
  success, not a transport failure, and must not be retried or retained in the offline spool.
- A validation error means the event could not be safely decoded or its path/media/limits were unsafe.
  Correct the producer; never bypass the scanner or relabel binary/archive content as JSON/text.
- An egress denial means no provider socket was acquired. The closed reason distinguishes no route,
  route/classification denial, sensitive taint, or local-only policy without exposing content.

## Diagnose an ignored capture

Inspect only the content-free privacy decision through an authorized diagnostic surface. Correlate by
event ID and verify:

1. policy ID, version, and SHA-256 match the expected Brain/repository revision;
2. disposition is `excluded` and egress is `deny`;
3. reason is `ignored_path`, `hidden_reasoning`, or `sensitive_content_excluded`;
4. the six ordered stage records show which later stages did not run; and
5. no `agent_events`, envelope, outbox, or append-audit row exists for the event.

Do not request raw content to diagnose an exclusion. Input/output digests, closed finding counts, and
rule/stage fingerprints are the intended evidence.

## Diagnose malformed or encoded input

Common safe validation codes include prohibited media/archive/binary, unsupported encoding, malformed
Unicode/JSON, duplicate keys, excessive depth/size/findings, and unsafe source path. Verify the adapter
is sending canonical JSON or supported UTF-8/UTF-16 text and a portable repository-relative path.

Never:

- unzip/decompress an archive and resubmit it automatically;
- replace an unsafe path with a fabricated safe path;
- disable duplicate-key/depth/size checks;
- decode and persist a failed payload for troubleshooting; or
- log scanner values, private blocks, secrets, PII, raw provider requests, or exception bodies.

Use a synthetic non-secret fixture to reproduce parser behavior. If a valid format is unsupported,
add it through a reviewed policy/scanner change with adversarial tests and a new immutable rule
revision.

## Diagnose unexpected classification or redaction

Compare the receipt’s policy version/digest, detector counts, stage digest, declared class, and output
digest. Re-evaluate a synthetic fixture against the exact historical revision; do not use the current
active policy for a historical decision. A deterministic replay must reproduce the same sanitized
bytes and evidence.

Secret/private findings raise classification to `restricted`; government/payment identifiers are
restricted; email/phone are at least confidential. A `local_only` action dominates all other classes,
retains content only in the authenticated encrypted event envelope, and remains unconditionally
non-egress. Repository policy cannot weaken its Brain policy.

If a detector false-positive is confirmed, create a reviewed next policy/scanner revision. Never edit
the old policy, receipt, event, or envelope; never downgrade classification merely to permit egress.

## Diagnose provider denial

Check, without credentials or payload:

1. the exact provider ID, public HTTPS origin/443, region, model ID, and purpose;
2. the active Brain policy and any narrower repository policy;
3. the final classification and whether any sensitive finding remains;
4. the stable downstream idempotency key; and
5. provider-gateway/network policy when application egress was allowed but transport failed.

An absent route, different host, path/query, alternate port, redirect target, IP literal, private/local
name, restricted/local-only class, or sensitive taint must remain denied. Never add a broad wildcard
route or send a diagnostic payload around `SanitizedProviderEgressHandler`.

## Integrity and recovery

Stop processing and run integrity/backup procedures if policy canonical bytes do not match their
digest, a privacy receipt conflicts with the same subject, encrypted event authentication fails, or
database constraints are violated. Do not delete the conflicting evidence.

After a crash, retry the original event ID with exact bytes. A fully committed sanitized/local-only
event returns `duplicate`; an excluded decision returns `ignored`; a rolled-back attempt can be
accepted normally. Confirm there is never a partial event without its privacy receipt or a receipt for
an accepted event without its event/outbox/audit transaction.

Close the incident only after the exact historical decision reproduces, secret canaries are absent
from plaintext durable storage/logs/provider calls, terminal ignored events are absent from spools,
and normal integrity/readiness checks pass.
