"""Lifecycle overlay models for mock remediation and human evidence review.

These records sit beside Flow 3/4 artifacts. They never mutate assessment.json
verdicts. The UI projects initial vs current status through AssessmentView.
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
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    APPLIED = "APPLIED"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"


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


class RemediationRecord(BaseModel):
    remediation_id: str
    control_id: str
    asset_id: str = ""
    issue: str = ""
    recommended_action: str = ""
    verification_method: str = "Mock verification scan"
    status: RemediationExecStatus = RemediationExecStatus.PENDING
    execution_result: str = ""
    verification_result: str = ""
    created_at: str = ""
    applied_at: str = ""
    verified_at: str = ""
    origin: RemediationOrigin = RemediationOrigin.SCAN


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
