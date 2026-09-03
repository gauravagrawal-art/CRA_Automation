"""Pydantic contracts for the Flow 2 evidence document.

These models describe collection outcomes only. No field in this module may
carry a compliance verdict; deciding whether missing evidence matters belongs
to the downstream assessment layer.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from src.config import EVIDENCE_SCHEMA_VERSION


class CollectionStatus(str, Enum):
    """The six collection outcomes defined by the Flow 2 contract."""

    COLLECTED = "COLLECTED"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    PARSE_ERROR = "PARSE_ERROR"
    NOT_COLLECTED = "NOT_COLLECTED"


class ReasonCode(str, Enum):
    """Detail attached to a non-COLLECTED status.

    New detail is expressed here rather than by adding top-level statuses.
    """

    PARAMETER_UNRESOLVED = "PARAMETER_UNRESOLVED"
    DOCUMENTARY_OR_HUMAN = "DOCUMENTARY_OR_HUMAN"
    INVALID_TOOL_PARAMETERS = "INVALID_TOOL_PARAMETERS"
    REQUIRED_NEW_TOOL = "REQUIRED_NEW_TOOL"
    TOOL_NOT_REGISTERED = "TOOL_NOT_REGISTERED"
    PATH_NOT_ALLOWED = "PATH_NOT_ALLOWED"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    REDACTION_FAILED = "REDACTION_FAILED"
    NORMALIZATION_FAILED = "NORMALIZATION_FAILED"
    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    PROVIDER_ERROR = "PROVIDER_ERROR"


class RequestedBy(BaseModel):
    """One approved evidence request that led to a call.

    Deduplicated calls carry several of these so no control/evidence-key link
    is lost.
    """

    control_id: str
    evidence_key: str
    required: bool = True


class EvidenceItem(BaseModel):
    evidence_id: str
    call_id: str
    requested_by: list[RequestedBy] = Field(default_factory=list)
    tool: str
    parameters_redacted: dict[str, Any] = Field(default_factory=dict)
    provider: str
    target_id: str
    collected_at: str
    status: CollectionStatus
    status_reason_code: ReasonCode | None = None
    status_message: str | None = None
    raw_artifact_ref: str | None = None
    raw_sha256: str | None = None
    normalized: dict[str, Any] | None = None
    normalized_sha256: str | None = None


class CollectionError(BaseModel):
    call_id: str
    requested_by: list[RequestedBy] = Field(default_factory=list)
    tool: str | None = None
    status: CollectionStatus
    reason_code: ReasonCode
    message: str


class CollectionSummary(BaseModel):
    controls_in_registry: int = 0
    evidence_requests_total: int = 0
    evidence_requests_technical: int = 0
    evidence_requests_documentary: int = 0
    evidence_requests_collectable: int = 0
    mcp_calls_planned: int = 0
    mcp_calls_deduplicated: int = 0
    evidence_items: int = 0
    collection_errors: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    by_reason_code: dict[str, int] = Field(default_factory=dict)
    by_tool: dict[str, int] = Field(default_factory=dict)


class RunMetadata(BaseModel):
    run_id: str
    target_id: str
    registry_version: str
    registry_hash: str
    registry_path: str
    target_profile_hash: str
    provider: str
    started_at: str
    completed_at: str | None = None
    application_id: str = ""
    schema_version: str = EVIDENCE_SCHEMA_VERSION


class EvidenceRun(BaseModel):
    run: RunMetadata
    evidence: list[EvidenceItem] = Field(default_factory=list)
    collection_errors: list[CollectionError] = Field(default_factory=list)
    summary: CollectionSummary = Field(default_factory=CollectionSummary)
