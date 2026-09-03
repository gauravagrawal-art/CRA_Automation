"""Map engine verdicts to simplified UI statuses.

The six Flow 3 verdicts are preserved on disk. Only the presentation layer
collapses them into PASS / FAIL / REVIEW / NOT_APPLICABLE.
"""

from __future__ import annotations

from src.assessment.models import Verdict
from src.compliance.models import OverallStatus, UIStatus


def map_verdict(verdict: Verdict | str) -> UIStatus:
    """Project a Flow 3 verdict onto a UI status."""
    value = verdict.value if isinstance(verdict, Verdict) else str(verdict)
    if value == Verdict.PASS.value:
        return UIStatus.PASS
    if value in (Verdict.FAIL.value, Verdict.PARTIAL.value):
        return UIStatus.FAIL
    if value == Verdict.NOT_APPLICABLE.value:
        return UIStatus.NOT_APPLICABLE
    # HUMAN_REVIEW_REQUIRED, INSUFFICIENT_EVIDENCE, unknown → REVIEW
    return UIStatus.REVIEW


def overall_status(
    *,
    failed: int,
    review: int,
    assessed: bool,
    remediation_pending: int = 0,
) -> OverallStatus:
    """Derive a one-line readiness label from UI counts."""
    if not assessed:
        return OverallStatus.NOT_ASSESSED
    if failed > 0 or remediation_pending > 0:
        return OverallStatus.NEEDS_ATTENTION
    if review > 0:
        return OverallStatus.NEEDS_REVIEW
    return OverallStatus.READY
