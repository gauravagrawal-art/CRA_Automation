"""Pydantic contracts for the Flow 3 assessment document.

The application owns every field here. Narrative text may be replaced by
Agent 2, but ``verdict``, ``severity``, identifiers, hashes and summary counts
are computed deterministically and are never read back from a model.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import AliasChoices, BaseModel, Field

from src.config import ASSESSMENT_SCHEMA_VERSION, DEFAULT_SEVERITY


class Verdict(str, Enum):
    """The six verdicts a control may receive."""

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"


#: Verdicts that carry a finding requiring remediation in Flow 4.
REMEDIATION_VERDICTS = {Verdict.FAIL, Verdict.PARTIAL}


class LimitationCode(str, Enum):
    """Machine-readable reasons the assessment is narrower than it looks."""

    LLM_NARRATIVE_UNAVAILABLE = "LLM_NARRATIVE_UNAVAILABLE"
    EVIDENCE_ASSOCIATION_UNKNOWN = "EVIDENCE_ASSOCIATION_UNKNOWN"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    EVALUATOR_ERROR = "EVALUATOR_ERROR"
    NO_APPROVED_SEVERITY_MODEL = "NO_APPROVED_SEVERITY_MODEL"
    NON_DETERMINISTIC_CONTROLS = "NON_DETERMINISTIC_CONTROLS"


class RuleTraceEntry(BaseModel):
    """One evaluated condition and the evidence it was resolved against.

    ``observed`` is the value itself when a single evidence item contributed,
    and a list in ``evidence_ids`` order when several did.
    """

    rule: dict[str, Any]
    observed: Any = None
    matched: bool
    evidence_ids: list[str] = Field(default_factory=list)
    note: str | None = None


class EvidenceGap(BaseModel):
    """Approved evidence the run did not collect."""

    evidence_key: str
    status: str
    reason_code: str | None = None
    required: bool = True


class DerivedPath(BaseModel):
    """A rule path computed by Flow 3 rather than observed by Flow 2."""

    path: str
    evidence_id: str
    basis: str


class ControlResult(BaseModel):
    control_id: str
    title: str
    source_traceability: dict[str, Any] = Field(default_factory=dict)
    verdict: Verdict
    evaluation_mode: str
    evaluator_trace: list[RuleTraceEntry] = Field(default_factory=list)
    evaluator_error: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    evidence_gaps: list[EvidenceGap] = Field(default_factory=list)
    derived_paths: list[DerivedPath] = Field(default_factory=list)
    expected_state: str = ""
    observed_state: str = ""
    reason: str = ""
    narrative_source: str = "template"
    severity: str = DEFAULT_SEVERITY
    remediation_required: bool = False
    remediation_seed: dict[str, Any] = Field(default_factory=dict)
    legal_requirement: dict[str, Any] = Field(default_factory=dict)
    nms_interpretation: str = ""
    technical_control: str = ""
    applicability: dict[str, Any] = Field(default_factory=dict)
    registry_human_review_flag: bool = False


class AssessmentSummary(BaseModel):
    total: int = 0
    # Serialized as "pass"; both spellings are accepted back so a stored
    # assessment.json re-reads into the same counts it was written from.
    passed: int = Field(
        default=0,
        serialization_alias="pass",
        validation_alias=AliasChoices("pass", "passed"),
    )
    fail: int = 0
    partial: int = 0
    insufficient_evidence: int = 0
    not_applicable: int = 0
    human_review_required: int = 0

    model_config = {"populate_by_name": True}


class Limitation(BaseModel):
    code: LimitationCode
    detail: str
    control_ids: list[str] = Field(default_factory=list)


class HumanReviewItem(BaseModel):
    control_id: str
    title: str
    verdict: Verdict
    reason: str


class AssessmentMetadata(BaseModel):
    assessment_id: str
    run_id: str
    target_id: str
    registry_version: str
    registry_hash: str
    evidence_sha256: str
    provider: str
    generated_at: str
    llm_narration: str
    application_id: str = ""
    schema_version: str = ASSESSMENT_SCHEMA_VERSION


class Assessment(BaseModel):
    metadata: AssessmentMetadata
    summary: AssessmentSummary = Field(default_factory=AssessmentSummary)
    results: list[ControlResult] = Field(default_factory=list)
    limitations: list[Limitation] = Field(default_factory=list)
    human_review_items: list[HumanReviewItem] = Field(default_factory=list)


#: Verdict -> ``AssessmentSummary`` field, so counts cannot drift from the enum.
SUMMARY_FIELD_BY_VERDICT = {
    Verdict.PASS: "passed",
    Verdict.FAIL: "fail",
    Verdict.PARTIAL: "partial",
    Verdict.INSUFFICIENT_EVIDENCE: "insufficient_evidence",
    Verdict.NOT_APPLICABLE: "not_applicable",
    Verdict.HUMAN_REVIEW_REQUIRED: "human_review_required",
}


def summarize(results: list[ControlResult]) -> AssessmentSummary:
    """Count verdicts. The application owns this; no model contributes to it."""
    summary = AssessmentSummary(total=len(results))
    for result in results:
        field = SUMMARY_FIELD_BY_VERDICT[result.verdict]
        setattr(summary, field, getattr(summary, field) + 1)
    return summary
