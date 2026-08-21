"""Discovery and loading of the artifacts a run leaves on disk.

Every document is parsed through the Pydantic contract that wrote it, so the
UI reads the same field names the application does and a schema change surfaces
here rather than as a silently missing value in a template.

Loads are cached on (path, mtime, size). A job that rewrites an artifact
changes at least one of those, so the next read picks the new file up.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, TypeVar

from src.assessment.models import Assessment, Verdict
from src.config import ASSESSMENTS_DIR, EVIDENCE_DIR
from src.evidence.models import EvidenceRun
from src.remediation.models import (
    ActionType,
    RemediationDocument,
    RemediationStatus,
    VerificationDocument,
)

T = TypeVar("T")

#: (path, mtime_ns, size) -> parsed document.
_CACHE: dict[tuple[str, int, int], Any] = {}


def _load_cached(path: Path, parse: Callable[[dict[str, Any]], T]) -> T | None:
    """Parse ``path`` through ``parse``, reusing the last result when unchanged."""
    try:
        stat = path.stat()
    except OSError:
        return None

    key = (str(path), stat.st_mtime_ns, stat.st_size)
    if key in _CACHE:
        return _CACHE[key]

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        parsed = parse(data)
    except (OSError, ValueError) as exc:  # includes json + pydantic failures
        raise ArtifactError(f"Could not read {path.name}: {exc}") from exc

    # A stale entry for the same path is now unreachable; drop it so a long
    # session does not accumulate one entry per rewrite.
    for stale in [k for k in _CACHE if k[0] == str(path)]:
        del _CACHE[stale]
    _CACHE[key] = parsed
    return parsed


class ArtifactError(RuntimeError):
    """An artifact exists but could not be parsed. The message is user-facing."""


def evidence_path(run_id: str, evidence_dir: Path | None = None) -> Path:
    return (evidence_dir or EVIDENCE_DIR) / run_id / "evidence.json"


def assessment_path(run_id: str, assessments_dir: Path | None = None) -> Path:
    return (assessments_dir or ASSESSMENTS_DIR) / run_id / "assessment.json"


def remediation_path(run_id: str, assessments_dir: Path | None = None) -> Path:
    return (assessments_dir or ASSESSMENTS_DIR) / run_id / "remediation.json"


def verification_path(run_id: str, assessments_dir: Path | None = None) -> Path:
    return (assessments_dir or ASSESSMENTS_DIR) / run_id / "verification.json"


def report_path(run_id: str, assessments_dir: Path | None = None) -> Path:
    return (assessments_dir or ASSESSMENTS_DIR) / run_id / "assessment.html"


def final_report_path(run_id: str, assessments_dir: Path | None = None) -> Path:
    return (assessments_dir or ASSESSMENTS_DIR) / run_id / "final-report.html"


def load_evidence(run_id: str) -> EvidenceRun | None:
    return _load_cached(evidence_path(run_id), EvidenceRun.model_validate)


def load_assessment(run_id: str) -> Assessment | None:
    return _load_cached(assessment_path(run_id), Assessment.model_validate)


def load_remediation(run_id: str) -> RemediationDocument | None:
    return _load_cached(remediation_path(run_id), RemediationDocument.model_validate)


def load_verification(run_id: str) -> VerificationDocument | None:
    return _load_cached(verification_path(run_id), VerificationDocument.model_validate)


@dataclass
class RunOverview:
    """What a run is and how far through the workflow it got.

    Counts come from the furthest artifact that exists: open findings are read
    from the remediation document when there is one, because that is where the
    application decided what counts as an action.
    """

    run_id: str
    target_id: str = ""
    provider: str = ""
    registry_version: str = ""
    registry_hash: str = ""
    started_at: str = ""
    has_evidence: bool = False
    has_assessment: bool = False
    has_remediation: bool = False
    has_verification: bool = False
    error: str | None = None
    verdict_counts: dict[str, int] = field(default_factory=dict)
    evidence_status_counts: dict[str, int] = field(default_factory=dict)
    open_findings: int = 0
    verified_closed: int = 0
    evidence_gaps: int = 0
    human_review: int = 0
    action_counts: dict[str, int] = field(default_factory=dict)
    baseline_comparable: bool = True

    @property
    def is_mock(self) -> bool:
        return self.provider == "mock"

    @property
    def stage_label(self) -> str:
        if self.has_verification:
            return "Verified"
        if self.has_remediation:
            return "Remediation composed"
        if self.has_assessment:
            return "Assessed"
        if self.has_evidence:
            return "Evidence collected"
        return "Empty"

    @property
    def assessment_result(self) -> str:
        """A one-word headline for the run history table."""
        if not self.has_assessment:
            return "Not assessed"
        if self.verdict_counts.get(Verdict.FAIL.value, 0):
            return "Findings open"
        if self.open_findings:
            return "Action required"
        return "No open findings"


def run_overview(run_id: str) -> RunOverview:
    """Assemble one run's headline facts, tolerating partial or broken artifacts."""
    overview = RunOverview(run_id=run_id)
    try:
        evidence = load_evidence(run_id)
        assessment = load_assessment(run_id)
        remediation = load_remediation(run_id)
        verification = load_verification(run_id)
    except ArtifactError as exc:
        overview.error = str(exc)
        return overview

    if evidence is not None:
        overview.has_evidence = True
        overview.target_id = evidence.run.target_id
        overview.provider = evidence.run.provider
        overview.registry_version = evidence.run.registry_version
        overview.registry_hash = evidence.run.registry_hash
        overview.started_at = evidence.run.started_at
        overview.evidence_status_counts = dict(evidence.summary.by_status)

    if assessment is not None:
        overview.has_assessment = True
        overview.target_id = assessment.metadata.target_id
        overview.provider = assessment.metadata.provider
        overview.registry_version = assessment.metadata.registry_version
        overview.registry_hash = assessment.metadata.registry_hash
        overview.started_at = overview.started_at or assessment.metadata.generated_at
        overview.verdict_counts = {
            verdict.value: sum(1 for r in assessment.results if r.verdict is verdict)
            for verdict in Verdict
        }
        overview.evidence_gaps = overview.verdict_counts[Verdict.INSUFFICIENT_EVIDENCE.value]
        overview.human_review = overview.verdict_counts[Verdict.HUMAN_REVIEW_REQUIRED.value]
        overview.open_findings = (
            overview.verdict_counts[Verdict.FAIL.value]
            + overview.verdict_counts[Verdict.PARTIAL.value]
        )

    if remediation is not None:
        overview.has_remediation = True
        overview.action_counts = dict(remediation.summary.by_action_type)
        overview.open_findings = remediation.summary.by_status.get(
            RemediationStatus.OPEN.value, 0
        )
        overview.verified_closed = remediation.summary.by_status.get(
            RemediationStatus.VERIFIED_CLOSED.value, 0
        )
        overview.evidence_gaps = remediation.summary.by_action_type.get(
            ActionType.EVIDENCE_RESOLUTION.value, overview.evidence_gaps
        )
        overview.human_review = remediation.summary.by_action_type.get(
            ActionType.HUMAN_REVIEW.value, overview.human_review
        )

    embedded = remediation.verification if remediation is not None else None
    if verification is not None or embedded is not None:
        doc = verification or embedded
        overview.has_verification = True
        overview.verified_closed = max(overview.verified_closed, doc.summary.verified_closed)
        overview.baseline_comparable = doc.baseline_comparable

    return overview


def list_run_ids(evidence_dir: Path | None = None, assessments_dir: Path | None = None) -> list[str]:
    """Every run directory that holds at least one artifact."""
    ids: set[str] = set()
    for base, marker in (
        (evidence_dir or EVIDENCE_DIR, "evidence.json"),
        (assessments_dir or ASSESSMENTS_DIR, "assessment.json"),
    ):
        if not base.exists():
            continue
        for child in base.iterdir():
            if child.is_dir() and (child / marker).exists():
                ids.add(child.name)
    return sorted(ids)


def list_runs() -> list[RunOverview]:
    """All runs, newest first by collection time."""
    runs = [run_overview(run_id) for run_id in list_run_ids()]
    runs.sort(key=lambda r: (r.started_at or "", r.run_id), reverse=True)
    return runs


def latest_run(runs: list[RunOverview] | None = None) -> RunOverview | None:
    """The newest run that produced an assessment, else the newest run at all."""
    candidates = runs if runs is not None else list_runs()
    if not candidates:
        return None
    for run in candidates:
        if run.has_assessment:
            return run
    return candidates[0]


def comparable_runs(runs: list[RunOverview]) -> list[RunOverview]:
    """Assessed runs sharing the newest run's target and registry hash.

    A trend across a changed registry baseline would compare different
    questions, so those runs are excluded rather than plotted together.
    """
    assessed = [r for r in runs if r.has_assessment and not r.error]
    if len(assessed) < 2:
        return []
    newest = assessed[0]
    series = [
        r
        for r in assessed
        if r.target_id == newest.target_id and r.registry_hash == newest.registry_hash
    ]
    if len(series) < 2:
        return []
    return list(reversed(series))


def previous_assessed_run(run_id: str, runs: list[RunOverview] | None = None) -> str | None:
    """The assessed run immediately before ``run_id`` on the same baseline."""
    candidates = runs if runs is not None else list_runs()
    assessed = [r for r in candidates if r.has_assessment and not r.error]
    current = next((r for r in assessed if r.run_id == run_id), None)
    if current is None:
        return None
    for run in assessed:
        if run.run_id == run_id:
            continue
        if (run.started_at or "") >= (current.started_at or ""):
            continue
        if run.target_id == current.target_id and run.registry_hash == current.registry_hash:
            return run.run_id
    return None
