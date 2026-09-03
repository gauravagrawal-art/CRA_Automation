"""Lifecycle overlay models for remediation actions and human evidence review.

These records sit beside Flow 3/4 artifacts. They never mutate assessment.json
verdicts. Finding closure remains OPEN / VERIFIED_CLOSED on Flow 4 items;
action statuses live here.
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from src.config import LIFECYCLE_SCHEMA_VERSION


class LifecycleStatus(str, Enum):
    """Current / initial status stored on the overlay (UI projection)."""

    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"
    REMEDIATION_PENDING = "REMEDIATION_PENDING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RemediationExecStatus(str, Enum):
    """Remediation-action lifecycle.

    Schema 1.1 writers use PROPOSED … BLOCKED. Legacy 1.0 values are retained
    so older lifecycle.json documents still parse.
    """

    # Legacy 1.0 (readable only)
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    APPLIED = "APPLIED"
    VERIFYING = "VERIFYING"

    # Schema 1.1 action lifecycle
    PROPOSED = "PROPOSED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    APPLYING = "APPLYING"
    APPLIED_UNVERIFIED = "APPLIED_UNVERIFIED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    BLOCKED = "BLOCKED"


#: Statuses written by the 1.1 action workflow.
ACTION_LIFECYCLE_STATUSES = frozenset(
    {
        RemediationExecStatus.PROPOSED,
        RemediationExecStatus.AWAITING_APPROVAL,
        RemediationExecStatus.APPROVED,
        RemediationExecStatus.APPLYING,
        RemediationExecStatus.APPLIED_UNVERIFIED,
        RemediationExecStatus.VERIFIED,
        RemediationExecStatus.FAILED,
        RemediationExecStatus.ROLLED_BACK,
        RemediationExecStatus.BLOCKED,
    }
)


class ApprovalAction(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"


class RemediationOrigin(str, Enum):
    SCAN = "SCAN"
    HUMAN_REVIEW = "HUMAN_REVIEW"


class EvidenceSource(str, Enum):
    AUTOMATED_SCAN = "AUTOMATED_SCAN"
    HUMAN_UPLOAD = "HUMAN_UPLOAD"
    SYSTEM_CONFIG = "SYSTEM_CONFIG"
    LLM_ANALYSIS = "LLM_ANALYSIS"
    VERIFICATION_SCAN = "VERIFICATION_SCAN"


class AnalysisDecision(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class EvidenceAttachment(BaseModel):
    filename: str
    stored_path: str = ""
    size_bytes: int = 0
    content_type: str = ""


class EvidenceSubmission(BaseModel):
    evidence_id: str
    control_id: str
    asset_id: str = ""
    description: str = ""
    attachments: list[EvidenceAttachment] = Field(default_factory=list)
    comments: str = ""
    source: EvidenceSource = EvidenceSource.HUMAN_UPLOAD
    submitted_by: str = "reviewer"
    submitted_at: str = ""


class EvidenceAnalysis(BaseModel):
    """Structured analyser output. Free-form LLM text never sets application status."""

    decision: AnalysisDecision
    reason: str = ""
    confidence: float = 0.0
    evidence_summary: str = ""
    ai_decision: AnalysisDecision | None = None
    human_decision: AnalysisDecision | None = None
    final_decision: AnalysisDecision | None = None
    override_reason: str = ""
    analysed_at: str = ""

    def resolve_final(self) -> AnalysisDecision:
        """Human decision is authoritative when present; otherwise AI decision."""
        if self.human_decision is not None:
            return self.human_decision
        if self.final_decision is not None:
            return self.final_decision
        if self.ai_decision is not None:
            return self.ai_decision
        return self.decision


class ReviewAttempt(BaseModel):
    attempt: int
    submission: EvidenceSubmission
    analysis: EvidenceAnalysis
    timestamp: str = ""


class StatusHistoryEntry(BaseModel):
    from_status: str = Field(alias="from")
    to_status: str = Field(alias="to")
    at: str = ""
    actor: str = ""
    reason: str = ""

    model_config = {"populate_by_name": True}


class ValidationResultEntry(BaseModel):
    at: str = ""
    ok: bool = False
    message: str = ""
    run_id: str = ""


class RollbackEvent(BaseModel):
    at: str = ""
    actor: str = ""
    reason: str = ""
    result: str = ""


class RemediationRecord(BaseModel):
    remediation_id: str
    control_id: str
    asset_id: str = ""
    issue: str = ""
    recommended_action: str = ""
    verification_method: str = "Fresh evidence collection and deterministic assessment"
    status: RemediationExecStatus = RemediationExecStatus.PROPOSED
    execution_result: str = ""
    verification_result: str = ""
    created_at: str = ""
    applied_at: str = ""
    verified_at: str = ""
    origin: RemediationOrigin = RemediationOrigin.SCAN

    # Schema 1.1 additive fields (defaults keep 1.0 documents loadable)
    finding_remediation_id: str = ""
    target_id: str = ""
    registry_hash: str = ""
    operation_id: str = ""
    observed_evidence: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    proposed_change: str = ""
    before_state: str = ""
    expected_after_state: str = ""
    change_reason: str = ""
    affected_component: str = ""
    service_restart_required: bool = False
    risk_and_impact: str = ""
    validation_method: str = ""
    rollback_method: str = ""
    approver: str = ""
    approved_at: str = ""
    approval_action: ApprovalAction | None = None
    actor: str = ""
    status_history: list[StatusHistoryEntry] = Field(default_factory=list)
    failure_reason: str = ""
    validation_results: list[ValidationResultEntry] = Field(default_factory=list)
    rollback_events: list[RollbackEvent] = Field(default_factory=list)
    apply_attempt_id: str = ""
    applied_overlay_hash: str = ""
    verification_run_id: str = ""
    verification_outcome: str = ""


class DatasetRecord(BaseModel):
    """Curated review row for future RAG / few-shot — not automatic training data."""

    control_id: str
    control_requirement: str = ""
    asset_type: str = ""
    evidence: str = ""
    human_decision: str = ""
    ai_decision: str = ""
    final_decision: str = ""
    decision_reason: str = ""
    remediation: str = ""
    verification_result: str = ""
    recorded_at: str = ""


class ControlLifecycle(BaseModel):
    control_id: str
    asset_id: str = ""
    initial_status: LifecycleStatus
    current_status: LifecycleStatus
    previous_status: LifecycleStatus | None = None
    initial_finding: str = ""
    initial_evidence: list[str] = Field(default_factory=list)
    remediations: list[RemediationRecord] = Field(default_factory=list)
    evidence_submissions: list[EvidenceSubmission] = Field(default_factory=list)
    review_attempts: list[ReviewAttempt] = Field(default_factory=list)
    dataset_records: list[DatasetRecord] = Field(default_factory=list)
    last_analysis: EvidenceAnalysis | None = None
    updated_at: str = ""


class LifecycleDocument(BaseModel):
    run_id: str
    assessment_id: str = ""
    schema_version: str = LIFECYCLE_SCHEMA_VERSION
    generated_at: str = ""
    updated_at: str = ""
    controls: dict[str, ControlLifecycle] = Field(default_factory=dict)


def make_remediation_id(run_id: str, control_id: str, origin: RemediationOrigin) -> str:
    digest = hashlib.sha256(
        f"{run_id}|{control_id}|{origin.value}".encode()
    ).hexdigest()
    return f"LREM-{digest[:12]}"


def make_evidence_id(run_id: str, control_id: str, attempt: int) -> str:
    digest = hashlib.sha256(
        f"{run_id}|{control_id}|{attempt}".encode()
    ).hexdigest()
    return f"HEV-{digest[:12]}"


def make_apply_attempt_id(remediation_id: str, clock: str) -> str:
    digest = hashlib.sha256(f"{remediation_id}|{clock}".encode()).hexdigest()
    return f"APPLY-{digest[:12]}"
