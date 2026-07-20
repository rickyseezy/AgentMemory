# ID-004 retrieval-scope operations runbook

## Readiness checks

1. Core readiness reports migration head `0006_id004_retrieval_scope`.
2. `scope_grants` contains `project_id`, `repository_id`, and `version`.
3. Every active grant has a positive version and valid interval.
4. The active Brain and installation security epoch are positive.

## Diagnosing a denial

Treat denial details as sensitive and do not enumerate inaccessible IDs. Verify, in order:

1. The bearer capability is current.
2. The requested grant belongs to the principal and Brain and is active at the request time.
3. The role permits recall; global additionally requires Owner or Admin.
4. Every requested Project/Repository/Checkout exists, is active, belongs to the Brain, and is
   covered by the grant narrowing.
5. Selected/global requests contain explicit Project IDs.

Do not bypass scope resolution, broaden a grant, or query canonical memory directly to diagnose a
denial. Use content-free audit correlation through `operation_id`.

## Related-scope behavior

Related expansion is capped at depth 3, 500 Projects, and the requested cost ceiling. It traverses
only active, confirmed repository topology among the preauthorized Project allowlist. A missing
related Project therefore means no active evidence path, no authorization, or a bound was reached;
it must not be silently added.

## Revocation response

On grant revocation, set `valid_to`, increment `version`, and increment the installation security
epoch through the governed authorization command when that command is introduced. Existing cache
entries are unusable because their grant revision/security epoch no longer matches. Never delete a
grant to revoke it.

## Rollback

Migration `0006` can downgrade only when there are no non-owner/scoped grants and no canonical rows
that reference grants. A refusal is a safety control. Export or migrate the dependent state under a
reviewed procedure; do not disable foreign keys or edit Alembic state manually.
