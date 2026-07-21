"""Shared SQLite visibility predicate for policy-invalidated source derivatives."""

from __future__ import annotations


def policy_visible_sql(repository: str, path: str) -> str:
    """Exclude a path until a later final include decision supersedes invalidation."""
    return (
        "NOT EXISTS (SELECT 1 FROM index_policy_derivative_invalidations AS policy_invalid "  # noqa: S608  # nosec B608
        f"WHERE policy_invalid.repository_id={repository} "
        f"AND policy_invalid.relative_path={path} "
        "AND NOT EXISTS (SELECT 1 FROM index_policy_decisions AS policy_decision "
        "WHERE policy_decision.repository_id=policy_invalid.repository_id "
        "AND policy_decision.relative_path=policy_invalid.relative_path "
        "AND policy_decision.decided_at>policy_invalid.invalidated_at "
        "AND policy_decision.disposition='include' AND policy_decision.phase='content' "
        "AND policy_decision.decision_id=(SELECT latest_decision.decision_id FROM "
        "index_policy_decisions AS latest_decision WHERE "
        "latest_decision.repository_id=policy_invalid.repository_id "
        "AND latest_decision.relative_path=policy_invalid.relative_path "
        "AND latest_decision.decided_at>policy_invalid.invalidated_at "
        "ORDER BY latest_decision.decided_at DESC,CASE latest_decision.phase "
        "WHEN 'content' THEN 1 ELSE 0 END DESC,latest_decision.decision_id DESC LIMIT 1)))"
    )
