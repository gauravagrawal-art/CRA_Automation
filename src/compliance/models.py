"""Normalized compliance view models shared by MOCK and future LLM providers.

These structures are what the UI and simplified reports render. Engine
artifacts (Assessment, EvidenceRun, RemediationDocument) remain the source of
truth for verdicts, hashes and audit traces.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AssetType(str, Enum):
    APPLICATION_SERVER = "APPLICATION_SERVER"
    DATABASE = "DATABASE"
    WEB_SERVER = "WEB_SERVER"
    ROUTER = "ROUTER"
    SWITCH = "SWITCH"
    FIREWALL = "FIREWALL"
    LOAD_BALANCER = "LOAD_BALANCER"
    GATEWAY = "GATEWAY"
    NETWORK_APPLIANCE = "NETWORK_APPLIANCE"
    VM = "VM"
    CONTAINER = "CONTAINER"
    OTHER = "OTHER"


class UIStatus(str, Enum):
    """Simplified status shown in the UI. Engine verdicts map into these."""

    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"
    REMEDIATION_PENDING = "REMEDIATION_PENDING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class OverallStatus(str, Enum):
    READY = "READY"
    NEEDS_REVIEW = "NEEDS REVIEW"
    NEEDS_ATTENTION = "NEEDS ATTENTION"
    NOT_ASSESSED = "NOT ASSESSED"


class DisplaySeverity(str, Enum):
    """Presentation severity overlay. Stored assessments remain UNCLASSIFIED."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class Asset(BaseModel):
    """A discovered or mock-inventory asset in an OSS / NMS environment."""

    asset_id: str
    name: str
    type: AssetType
    hostname: str | None = None
    ip_address: str | None = None
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    operating_system: str | None = None
    management_interfaces: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    discovery_source: str = "mock_inventory"


class EvidenceFact(BaseModel):
    """One short factual observation tied to collected evidence."""

    text: str
    evidence_ids: list[str] = Field(default_factory=list)


class ReviewHistoryEntry(BaseModel):
    """One human-evidence attempt for collapsed audit display."""

    attempt: int
    evidence: str = ""
    decision: str = ""
    reason: str = ""
    timestamp: str = ""


class ControlView(BaseModel):
    """Concise control view for the compliance UI."""

    control_id: str
    title: str
    requirement: str = ""
    asset_ids: list[str] = Field(default_factory=list)
    status: UIStatus
    initial_status: UIStatus | None = None
    previous_status: UIStatus | None = None
    severity: DisplaySeverity = DisplaySeverity.NONE
    evidence: list[EvidenceFact] = Field(default_factory=list)
    finding: str = ""
    remediation: str = ""
    verification: str = ""
    reason: str = ""
    engine_verdict: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    remediation_applied: bool = False
    remediation_status: str = ""
    finding_status: str = "OPEN"
    can_apply_remediation: bool = False
    can_propose_remediation: bool = False
    can_approve_remediation: bool = False
    can_rollback_remediation: bool = False
    apply_blocked_reason: str = ""
    can_submit_evidence: bool = False
    analysis_decision: str = ""
    analysis_reason: str = ""
    review_history: list[ReviewHistoryEntry] = Field(default_factory=list)
    proposed_change: str = ""
    affected_component: str = ""
    service_restart_required: bool = False
    risk_and_impact: str = ""
    rollback_method: str = ""
    rem_approver: str = ""
    rem_approved_at: str = ""
    # Audit fields kept for expandable detail; not primary UI content.
    audit: dict[str, Any] = Field(default_factory=dict)


class FindingView(BaseModel):
    control_id: str
    control_title: str = ""
    asset_id: str
    asset_name: str = ""
    status: UIStatus
    severity: DisplaySeverity = DisplaySeverity.NONE
    finding: str = ""
    evidence_ids: list[str] = Field(default_factory=list)


class RemediationView(BaseModel):
    remediation_id: str
    control_id: str
    control_title: str = ""
    asset_id: str
    asset_name: str = ""
    severity: DisplaySeverity = DisplaySeverity.NONE
    issue: str = ""
    recommended_action: str = ""
    verification: str = ""
    status: str = "OPEN"
    finding_status: str = "OPEN"
    action_status: str = ""
    action_type: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    proposed_change: str = ""
    before_state: str = ""
    expected_after_state: str = ""
    risk_and_impact: str = ""
    rollback_method: str = ""
    service_restart_required: bool = False
    affected_component: str = ""
    failure_reason: str = ""
    can_propose: bool = False
    can_approve: bool = False
    can_apply: bool = False
    can_rollback: bool = False
    apply_blocked_reason: str = ""
    approver: str = ""
    approved_at: str = ""


class AssessmentSummaryView(BaseModel):
    overall_status: OverallStatus = OverallStatus.NOT_ASSESSED
    assets_assessed: int = 0
    controls_assessed: int = 0
    passed: int = 0
    failed: int = 0
    review: int = 0
    remediation_pending: int = 0
    not_applicable: int = 0
    critical_high_findings: int = 0
    initially_passed: int = 0
    passed_after_remediation: int = 0
    passed_after_review: int = 0
    remaining_failed: int = 0
    pending_human_review: int = 0
    bullets: list[str] = Field(default_factory=list)


class AssessmentView(BaseModel):
    """Normalized assessment consumed by UI and simplified reports."""

    run_id: str = ""
    assessment_id: str = ""
    target_id: str = ""
    application_id: str = ""
    provider: str = ""
    registry_version: str = ""
    registry_hash: str = ""
    evidence_sha256: str = ""
    generated_at: str = ""
    is_mock: bool = True
    summary: AssessmentSummaryView = Field(default_factory=AssessmentSummaryView)
    assets: list[Asset] = Field(default_factory=list)
    controls: list[ControlView] = Field(default_factory=list)
    findings: list[FindingView] = Field(default_factory=list)
    remediations: list[RemediationView] = Field(default_factory=list)
    top_findings: list[FindingView] = Field(default_factory=list)
