"""Pydantic contracts for the Flow 4 remediation and verification documents.

Every field here is written by application code. No model contributes to an
identifier, a hash, a verdict, a status or a recommendation: a recommendation
is copied verbatim from the approved registry or the item is not a technical
remediation at all.
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

from src.assessment.models import Verdict
from src.config import (
    REMEDIATION_OWNER,
    REMEDIATION_SCHEMA_VERSION,
    VERIFICATION_SCHEMA_VERSION,
)


class ActionType(str, Enum):
    """What a finding asks a human to do.

    ``EVIDENCE_RESOLUTION`` and ``HUMAN_REVIEW`` are deliberately not technical
    fixes: uncollected evidence and an unresolved decision are not defects of
    the target and must not be presented as ones.
    """

    TECHNICAL_REMEDIATION = "TECHNICAL_REMEDIATION"
    EVIDENCE_RESOLUTION = "EVIDENCE_RESOLUTION"
    HUMAN_REVIEW = "HUMAN_REVIEW"


class RemediationStatus(str, Enum):
    """Lifecycle states this POC implements.

    ``ACTIONED_NOT_VERIFIED``, ``ACCEPTED_RISK`` and ``NOT_APPLICABLE`` are
    reserved for later versions and are intentionally absent. ``ACCEPTED_RISK``
    in particular would require an explicit human identity, timestamp and
    rationale, and can never be set by an automated component.
    """

    OPEN = "OPEN"
    VERIFIED_CLOSED = "VERIFIED_CLOSED"


class RemediationReasonCode(str, Enum):
    """Why an item is not a plain technical remediation."""

    REMEDIATION_GUIDANCE_NOT_APPROVED = "REMEDIATION_GUIDANCE_NOT_APPROVED"
    REQUIRED_EVIDENCE_NOT_COLLECTED = "REQUIRED_EVIDENCE_NOT_COLLECTED"
    EVIDENCE_COLLECTION_ERROR = "EVIDENCE_COLLECTION_ERROR"
    HUMAN_DECISION_REQUIRED = "HUMAN_DECISION_REQUIRED"


class VerificationOutcome(str, Enum):
    """The result of comparing a previous finding with a later assessment."""

    VERIFIED_CLOSED = "VERIFIED_CLOSED"
    STILL_OPEN = "STILL_OPEN"
    VERIFICATION_BLOCKED = "VERIFICATION_BLOCKED"


class VerificationReasonCode(str, Enum):
    """Why a finding did not reach ``VERIFIED_CLOSED``."""

    NOT_A_NEW_SCAN = "NOT_A_NEW_SCAN"
    TARGET_MISMATCH = "TARGET_MISMATCH"
    REGISTRY_BASELINE_CHANGED = "REGISTRY_BASELINE_CHANGED"
    CONTROL_NOT_ASSESSED = "CONTROL_NOT_ASSESSED"
    NEW_VERDICT_NOT_PASS = "NEW_VERDICT_NOT_PASS"
    REQUIRED_EVIDENCE_NOT_COLLECTED = "REQUIRED_EVIDENCE_NOT_COLLECTED"


#: Document-level blocks: no finding in the pair can be compared at all.
BASELINE_REASON_CODES = {
    VerificationReasonCode.NOT_A_NEW_SCAN,
    VerificationReasonCode.TARGET_MISMATCH,
    VerificationReasonCode.REGISTRY_BASELINE_CHANGED,
}

#: Verdicts that leave nothing to remediate or to verify.
CLEAR_VERDICTS = {Verdict.PASS, Verdict.NOT_APPLICABLE}


class VerificationRequirement(BaseModel):
    """What a later scan must show before this finding may be closed.

    Populated entirely from the approved control: the evidence keys come from
    ``remediation_seed.verification_evidence_keys`` and the tools from the
    matching ``evidence_plan`` entries.
    """

    control_id: str
    registry_version: str
    registry_hash: str
    evidence_keys: list[str] = Field(default_factory=list)
    mcp_tools: list[str] = Field(default_factory=list)
    required_post_verdict: Literal["PASS"] = "PASS"
    same_target_required: Literal[True] = True


class RemediationItem(BaseModel):
    """One advisory action derived from one assessed control.

    ``recommendation`` is either the approved seed text verbatim or empty. This
    application never composes remediation prose and never emits a command:
    ``automatic_execution`` is pinned to ``False`` by the type itself.
    """

    remediation_id: str
    assessment_id: str
    run_id: str
    target_id: str
    finding_control_id: str
    finding_title: str = ""
    finding_verdict: Verdict
    action_type: ActionType
    evidence_ids: list[str] = Field(default_factory=list)
    failed_rule_refs: list[str] = Field(default_factory=list)
    missing_evidence_keys: list[str] = Field(default_factory=list)
    observed_state: str = ""
    recommendation: str = ""
    recommendation_source: str = "APPROVED_REGISTRY_REMEDIATION_SEED"
    reason: str = ""
    reason_code: RemediationReasonCode | None = None
    implementation_owner: str = REMEDIATION_OWNER
    automatic_execution: Literal[False] = False
    verification: VerificationRequirement | None = None
    status: RemediationStatus = RemediationStatus.OPEN


class RemediationSummary(BaseModel):
    controls_assessed: int = 0
    controls_without_action: int = 0
    items_total: int = 0
    by_action_type: dict[str, int] = Field(
        default_factory=lambda: {action.value: 0 for action in ActionType}
    )
    by_status: dict[str, int] = Field(
        default_factory=lambda: {status.value: 0 for status in RemediationStatus}
    )


class RemediationMetadata(BaseModel):
    remediation_run_id: str
    assessment_id: str
    run_id: str
    target_id: str
    registry_version: str
    registry_hash: str
    evidence_sha256: str
    assessment_sha256: str
    provider: str
    generated_at: str
    schema_version: str = REMEDIATION_SCHEMA_VERSION


class VerificationItem(BaseModel):
    """One previous finding checked against a later assessment."""

    control_id: str
    title: str = ""
    previous_remediation_id: str | None = None
    previous_verdict: Verdict
    new_verdict: Verdict | None = None
    outcome: VerificationOutcome
    reason_code: VerificationReasonCode | None = None
    reason: str = ""
    new_evidence_ids: list[str] = Field(default_factory=list)


class VerificationSummary(BaseModel):
    findings_compared: int = 0
    verified_closed: int = 0
    still_open: int = 0
    blocked: int = 0


class VerificationMetadata(BaseModel):
    previous_run_id: str
    new_run_id: str
    previous_assessment_id: str
    new_assessment_id: str
    previous_target_id: str
    new_target_id: str
    previous_registry_version: str
    new_registry_version: str
    previous_registry_hash: str
    new_registry_hash: str
    generated_at: str
    schema_version: str = VERIFICATION_SCHEMA_VERSION


class VerificationDocument(BaseModel):
    """Closure decisions for the findings of an earlier assessment.

    ``baseline_comparable`` is false when the two assessments cannot be treated
    as the same baseline at all. Nothing closes in that case, regardless of the
    later verdicts.
    """

    metadata: VerificationMetadata
    baseline_comparable: bool = True
    blocked_reason_code: VerificationReasonCode | None = None
    summary: VerificationSummary = Field(default_factory=VerificationSummary)
    items: list[VerificationItem] = Field(default_factory=list)


class RemediationDocument(BaseModel):
    metadata: RemediationMetadata
    summary: RemediationSummary = Field(default_factory=RemediationSummary)
    items: list[RemediationItem] = Field(default_factory=list)
    verification: VerificationDocument | None = None


def make_remediation_id(assessment_id: str, control_id: str, action_type: ActionType) -> str:
    """A stable ID for a finding, so re-running Flow 4 is byte-identical."""
    digest = hashlib.sha256(
        f"{assessment_id}|{control_id}|{action_type.value}".encode()
    ).hexdigest()
    return f"REM-{digest[:12]}"


def summarize(items: list[RemediationItem], controls_assessed: int) -> RemediationSummary:
    """Count items by action type and status. The application owns these counts."""
    summary = RemediationSummary(
        controls_assessed=controls_assessed,
        controls_without_action=controls_assessed - len(items),
        items_total=len(items),
    )
    for item in items:
        summary.by_action_type[item.action_type.value] += 1
        summary.by_status[item.status.value] += 1
    return summary
