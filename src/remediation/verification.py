"""Evidence-backed closure of findings.

A finding closes when a later assessment, produced from newly collected
evidence under the same approved baseline, returns ``PASS`` for the same
control on the same target. Nothing else closes it: not a recommendation, not a
statement that a change was applied, not an operator's judgement. This module
takes two assessment documents and nothing else, so there is no input through
which a claim could be asserted.
"""

from __future__ import annotations

from src.assessment.models import Assessment, ControlResult, Verdict
from src.remediation.composer import action_type_for
from src.remediation.models import (
    CLEAR_VERDICTS,
    VerificationDocument,
    VerificationItem,
    VerificationMetadata,
    VerificationOutcome,
    VerificationReasonCode,
    VerificationSummary,
    make_remediation_id,
)

BASELINE_MESSAGES = {
    VerificationReasonCode.NOT_A_NEW_SCAN: (
        "Both assessments describe the same run. Closure requires a new evidence "
        "collection through Flow 2 and a new assessment through Flow 3."
    ),
    VerificationReasonCode.TARGET_MISMATCH: (
        "The assessments describe different targets, so their controls are not "
        "the same finding."
    ),
    VerificationReasonCode.REGISTRY_BASELINE_CHANGED: (
        "The approved registry changed between the assessments. The control may "
        "be reassessed under the new baseline, but that is not verified closure "
        "under the old one."
    ),
}


def _baseline_block(
    previous: Assessment, new: Assessment
) -> VerificationReasonCode | None:
    """Reasons the two assessments cannot be compared as one baseline at all."""
    old, fresh = previous.metadata, new.metadata
    if old.run_id == fresh.run_id:
        return VerificationReasonCode.NOT_A_NEW_SCAN
    if old.target_id != fresh.target_id:
        return VerificationReasonCode.TARGET_MISMATCH
    if old.registry_hash != fresh.registry_hash or old.registry_version != fresh.registry_version:
        return VerificationReasonCode.REGISTRY_BASELINE_CHANGED
    return None


def _findings(assessment: Assessment) -> list[ControlResult]:
    return [result for result in assessment.results if result.verdict not in CLEAR_VERDICTS]


def _previous_remediation_id(assessment: Assessment, result: ControlResult) -> str | None:
    """The ID Flow 4 gave this finding, so a closure links back to its item."""
    seed = result.remediation_seed or {}
    action = action_type_for(result.verdict, (seed.get("recommendation") or "").strip())
    if action is None:
        return None
    return make_remediation_id(assessment.metadata.assessment_id, result.control_id, action)


def _required_gaps(result: ControlResult) -> list[str]:
    return [gap.evidence_key for gap in result.evidence_gaps if gap.required]


def _decide(previous_result: ControlResult, new_result: ControlResult | None) -> tuple[
    VerificationOutcome, VerificationReasonCode | None, str
]:
    """Closure decision for one control under an already-comparable baseline."""
    if new_result is None:
        return (
            VerificationOutcome.VERIFICATION_BLOCKED,
            VerificationReasonCode.CONTROL_NOT_ASSESSED,
            "The later assessment does not report this control, so its state is unknown.",
        )

    if new_result.verdict != Verdict.PASS:
        if new_result.verdict == Verdict.INSUFFICIENT_EVIDENCE:
            return (
                VerificationOutcome.STILL_OPEN,
                VerificationReasonCode.REQUIRED_EVIDENCE_NOT_COLLECTED,
                "The later assessment could not resolve the required evidence, "
                "which is not the same as the finding being fixed.",
            )
        return (
            VerificationOutcome.STILL_OPEN,
            VerificationReasonCode.NEW_VERDICT_NOT_PASS,
            f"The later verdict is {new_result.verdict.value}; only PASS closes a finding.",
        )

    missing = _required_gaps(new_result)
    if missing:
        return (
            VerificationOutcome.STILL_OPEN,
            VerificationReasonCode.REQUIRED_EVIDENCE_NOT_COLLECTED,
            "The later run did not collect required evidence: " + ", ".join(missing),
        )
    if not new_result.evidence_ids:
        return (
            VerificationOutcome.STILL_OPEN,
            VerificationReasonCode.REQUIRED_EVIDENCE_NOT_COLLECTED,
            "The later verdict is not backed by any collected evidence.",
        )

    return (
        VerificationOutcome.VERIFIED_CLOSED,
        None,
        "A later evidence-backed assessment returned PASS for this control on the "
        "same target under the same approved baseline.",
    )


def verify(previous: Assessment, new: Assessment, *, generated_at: str) -> VerificationDocument:
    """Compare an earlier assessment's findings with a later assessment."""
    old, fresh = previous.metadata, new.metadata
    metadata = VerificationMetadata(
        previous_run_id=old.run_id,
        new_run_id=fresh.run_id,
        previous_assessment_id=old.assessment_id,
        new_assessment_id=fresh.assessment_id,
        previous_target_id=old.target_id,
        new_target_id=fresh.target_id,
        previous_registry_version=old.registry_version,
        new_registry_version=fresh.registry_version,
        previous_registry_hash=old.registry_hash,
        new_registry_hash=fresh.registry_hash,
        generated_at=generated_at,
    )

    blocked = _baseline_block(previous, new)
    new_results = {result.control_id: result for result in new.results}
    items: list[VerificationItem] = []

    for result in _findings(previous):
        new_result = new_results.get(result.control_id)
        if blocked is not None:
            outcome: VerificationOutcome = VerificationOutcome.VERIFICATION_BLOCKED
            reason_code: VerificationReasonCode | None = blocked
            reason = BASELINE_MESSAGES[blocked]
        else:
            outcome, reason_code, reason = _decide(result, new_result)
        items.append(
            VerificationItem(
                control_id=result.control_id,
                title=result.title,
                previous_remediation_id=_previous_remediation_id(previous, result),
                previous_verdict=result.verdict,
                new_verdict=new_result.verdict if new_result else None,
                outcome=outcome,
                reason_code=reason_code,
                reason=reason,
                new_evidence_ids=list(new_result.evidence_ids) if new_result else [],
            )
        )

    summary = VerificationSummary(
        findings_compared=len(items),
        verified_closed=sum(1 for i in items if i.outcome == VerificationOutcome.VERIFIED_CLOSED),
        still_open=sum(1 for i in items if i.outcome == VerificationOutcome.STILL_OPEN),
        blocked=sum(1 for i in items if i.outcome == VerificationOutcome.VERIFICATION_BLOCKED),
    )

    return VerificationDocument(
        metadata=metadata,
        baseline_comparable=blocked is None,
        blocked_reason_code=blocked,
        summary=summary,
        items=items,
    )
