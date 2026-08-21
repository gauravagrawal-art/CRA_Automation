"""Pydantic contracts for document registry and draft controls."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from src.config import (
    CRA_CATEGORY,
    CRA_CATEGORY_NAME,
    CRA_CLASS,
    PRODUCT_NAME,
    REGISTRY_VERSION,
    SCHEMA_VERSION,
)


class ApplicabilityStatus(str, Enum):
    APPLICABLE = "APPLICABLE"
    CONDITIONAL = "CONDITIONAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"


class EvidenceMode(str, Enum):
    TECHNICAL = "TECHNICAL"
    DOCUMENTARY_OR_HUMAN = "DOCUMENTARY_OR_HUMAN"


class ToolStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    REQUIRED_NEW_TOOL = "REQUIRED_NEW_TOOL"


class EvaluationMode(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"
    HUMAN_OR_AGENT_REASONING = "HUMAN_OR_AGENT_REASONING"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ParameterStatus(str, Enum):
    RESOLVED = "RESOLVED"
    TO_BE_PROVIDED = "TO_BE_PROVIDED"


class SourceLocator(BaseModel):
    page: int | None = None
    article: str | None = None
    annex: str | None = None
    part: str | None = None
    section: str | None = None
    paragraph: str | None = None
    clause: str | None = None


class SourceReference(BaseModel):
    document_id: str
    source_locator: SourceLocator
    source_excerpt: str
    normalized_summary: str | None = None
    binding_status: str | None = None


class DocumentEntry(BaseModel):
    document_id: str
    filename: str
    title: str
    issuer: str
    source_type: str
    binding_status: str
    document_status: str
    authority_level: int
    version_date: str | None = None
    sha256: str | None = None
    page_count: int | None = None
    present: bool = True
    tier: str = "authoritative"


class RequirementEntry(BaseModel):
    requirement_id: str
    legal_requirement_text: str
    normalized_requirement: str
    source_reference: SourceReference
    cra_annex: str = "I"
    cra_part: str | None = None
    cra_point: str | None = None


class ConflictEntry(BaseModel):
    conflict_id: str
    description: str
    sources: list[str] = Field(default_factory=list)
    precedence_applied: str | None = None
    human_review_required: bool = True
    details: dict[str, Any] = Field(default_factory=dict)


class HumanReviewItem(BaseModel):
    item_id: str
    reason: str
    related_requirement_id: str | None = None
    related_control_id: str | None = None


class UnresolvedItem(BaseModel):
    item_id: str
    description: str
    source_document_id: str | None = None


class DocumentRegistryMetadata(BaseModel):
    schema_version: str = SCHEMA_VERSION
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    product: str = PRODUCT_NAME
    declared_classification: dict[str, str] = Field(
        default_factory=lambda: {
            "class": CRA_CLASS,
            "category": CRA_CATEGORY,
            "name": CRA_CATEGORY_NAME,
        }
    )


class DocumentRegistry(BaseModel):
    metadata: DocumentRegistryMetadata
    documents: list[DocumentEntry] = Field(default_factory=list)
    requirements: list[RequirementEntry] = Field(default_factory=list)
    classification_references: list[SourceReference] = Field(default_factory=list)
    guidance_references: list[SourceReference] = Field(default_factory=list)
    technical_references: list[SourceReference] = Field(default_factory=list)
    standardisation_references: list[SourceReference] = Field(default_factory=list)
    conflicts: list[ConflictEntry] = Field(default_factory=list)
    human_review_items: list[HumanReviewItem] = Field(default_factory=list)
    unresolved_items: list[UnresolvedItem] = Field(default_factory=list)
    injection_candidates: list[dict[str, Any]] = Field(default_factory=list)


class SourceTraceability(BaseModel):
    legal_sources: list[SourceReference] = Field(default_factory=list)
    classification_sources: list[SourceReference] = Field(default_factory=list)
    guidance_sources: list[SourceReference] = Field(default_factory=list)
    technical_reference_sources: list[SourceReference] = Field(default_factory=list)


class Applicability(BaseModel):
    status: ApplicabilityStatus
    reason: str
    assumptions: list[str] = Field(default_factory=list)


class LegalRequirement(BaseModel):
    original_text: str
    normalized_requirement: str


class ComponentTarget(BaseModel):
    component: str
    interface_type: str | None = None
    protocol: str | None = None
    port: int | None = None
    config_path: str | None = None


class TargetContext(BaseModel):
    components: list[ComponentTarget] = Field(default_factory=list)
    platform: str | None = None


class EvidencePlanItem(BaseModel):
    evidence_key: str
    description: str
    mode: EvidenceMode
    mcp_tool: str | None = None
    tool_status: ToolStatus = ToolStatus.AVAILABLE
    parameters: dict[str, Any] = Field(default_factory=dict)
    parameter_status: ParameterStatus = ParameterStatus.RESOLVED
    required: bool = True


class RemediationSeed(BaseModel):
    recommendation: str
    verification_evidence_keys: list[str] = Field(default_factory=list)


class Evaluation(BaseModel):
    mode: EvaluationMode
    rules: list[dict[str, Any]] = Field(default_factory=list)


class Control(BaseModel):
    control_id: str
    title: str
    source_traceability: SourceTraceability
    applicability: Applicability
    legal_requirement: LegalRequirement
    nms_interpretation: str
    technical_control: str
    target_context: TargetContext | None = None
    evidence_plan: list[EvidencePlanItem] = Field(default_factory=list)
    assertion_refs: list[str] = Field(default_factory=list)
    evaluation: Evaluation
    remediation_seed: RemediationSeed
    human_review_required: bool = False
    confidence: Confidence = Confidence.HIGH
    etsi_requirement_ids: list[str] = Field(default_factory=list)


class ControlsDraftMetadata(BaseModel):
    schema_version: str = SCHEMA_VERSION
    registry_version: str = REGISTRY_VERSION
    status: str = "DRAFT"
    product: str = PRODUCT_NAME
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    product_profile_sha256: str | None = None
    security_assertions_sha256: str | None = None


class ControlsDraft(BaseModel):
    metadata: ControlsDraftMetadata
    controls: list[Control] = Field(default_factory=list)


class ApprovalManifest(BaseModel):
    version: str
    approver: str
    approved_at: str
    source_registry_hash: str
    approved_registry_hash: str
    source_document_registry_hash: str | None = None
