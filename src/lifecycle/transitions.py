"""Explicit allowed transitions for remediation-action statuses."""

from __future__ import annotations

from src.lifecycle.models import RemediationExecStatus

ALLOWED_TRANSITIONS: dict[RemediationExecStatus, frozenset[RemediationExecStatus]] = {
    RemediationExecStatus.PROPOSED: frozenset(
        {RemediationExecStatus.AWAITING_APPROVAL}
    ),
    RemediationExecStatus.AWAITING_APPROVAL: frozenset(
        {
            RemediationExecStatus.APPROVED,
            RemediationExecStatus.PROPOSED,
        }
    ),
    RemediationExecStatus.APPROVED: frozenset(
        {
            RemediationExecStatus.APPLYING,
            RemediationExecStatus.BLOCKED,
        }
    ),
    RemediationExecStatus.APPLYING: frozenset(
        {
            RemediationExecStatus.APPLIED_UNVERIFIED,
            RemediationExecStatus.FAILED,
        }
    ),
    RemediationExecStatus.APPLIED_UNVERIFIED: frozenset(
        {
            RemediationExecStatus.VERIFIED,
            RemediationExecStatus.FAILED,
            RemediationExecStatus.BLOCKED,
            RemediationExecStatus.ROLLED_BACK,
        }
    ),
    RemediationExecStatus.FAILED: frozenset(
        {
            RemediationExecStatus.APPROVED,
            RemediationExecStatus.ROLLED_BACK,
            RemediationExecStatus.BLOCKED,
        }
    ),
    RemediationExecStatus.BLOCKED: frozenset(
        {RemediationExecStatus.APPROVED}
    ),
    RemediationExecStatus.ROLLED_BACK: frozenset(
        {
            RemediationExecStatus.PROPOSED,
            RemediationExecStatus.AWAITING_APPROVAL,
            RemediationExecStatus.APPROVED,
        }
    ),
    RemediationExecStatus.VERIFIED: frozenset(),
    # Legacy 1.0 — no new writers; keep empty allow-sets so transitions refuse.
    RemediationExecStatus.NOT_REQUIRED: frozenset(),
    RemediationExecStatus.PENDING: frozenset(
        {
            RemediationExecStatus.AWAITING_APPROVAL,
            RemediationExecStatus.PROPOSED,
        }
    ),
    RemediationExecStatus.IN_PROGRESS: frozenset(
        {
            RemediationExecStatus.APPLIED_UNVERIFIED,
            RemediationExecStatus.FAILED,
            RemediationExecStatus.APPLYING,
        }
    ),
    RemediationExecStatus.APPLIED: frozenset(
        {
            RemediationExecStatus.APPLIED_UNVERIFIED,
            RemediationExecStatus.ROLLED_BACK,
            RemediationExecStatus.FAILED,
        }
    ),
    RemediationExecStatus.VERIFYING: frozenset(
        {
            RemediationExecStatus.VERIFIED,
            RemediationExecStatus.FAILED,
        }
    ),
}


def can_transition(
    current: RemediationExecStatus, target: RemediationExecStatus
) -> bool:
    if current is target:
        return True
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())


def assert_transition(
    current: RemediationExecStatus, target: RemediationExecStatus
) -> None:
    if can_transition(current, target):
        return
    raise ValueError(
        f"Invalid remediation-action transition: {current.value} → {target.value}."
    )
