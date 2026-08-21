"""Flow 4 orchestrator: preflight, compose, verify, render.

Both entry points are pure functions of artifacts already on disk. Flow 4 never
calls Infrastructure MCP and never re-collects evidence: a re-scan means running
Flow 2 and Flow 3 again, and this module only reads what they wrote.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from src.assessment.models import Assessment
from src.config import ASSESSMENTS_DIR, EVIDENCE_DIR
from src.evidence.io import atomic_write_text, write_json_artifact
from src.registry.approval import compute_hash
from src.remediation.composer import compose
from src.remediation.models import (
    RemediationDocument,
    RemediationMetadata,
    VerificationDocument,
    summarize,
)
from src.remediation.preflight import (
    RemediationPreflightError,
    RemediationPreflightResult,
    load_assessment,
    remediation_preflight,
)
from src.remediation.report import render_final_html
from src.remediation.verification import verify

__all__ = ["remediate", "verify_runs", "RemediationPreflightError"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_remediation_run_id(assessment_id: str, generated_at: str) -> str:
    digest = compute_hash({"assessment_id": assessment_id, "generated_at": generated_at})
    return f"REMED-{digest[:12]}"


def assessment_path_for(run_id: str, assessments_dir: Path | None = None) -> Path:
    return (assessments_dir or ASSESSMENTS_DIR) / run_id / "assessment.json"


def build_remediation(
    pre: RemediationPreflightResult,
    *,
    previous_assessment: Assessment | None = None,
    clock: Callable[[], str] | None = None,
) -> RemediationDocument:
    """Compose the remediation document in memory, verification included."""
    now = clock or _utc_now
    generated_at = now()
    assessment = pre.assessment
    meta = assessment.metadata

    items = compose(assessment, pre.registry)
    verification = (
        verify(previous_assessment, assessment, generated_at=generated_at)
        if previous_assessment is not None
        else None
    )

    return RemediationDocument(
        metadata=RemediationMetadata(
            remediation_run_id=make_remediation_run_id(meta.assessment_id, generated_at),
            assessment_id=meta.assessment_id,
            run_id=meta.run_id,
            target_id=meta.target_id,
            registry_version=meta.registry_version,
            registry_hash=pre.registry_hash,
            evidence_sha256=pre.evidence_sha256,
            assessment_sha256=pre.assessment_sha256,
            provider=meta.provider,
            generated_at=generated_at,
        ),
        summary=summarize(items, controls_assessed=len(assessment.results)),
        items=items,
        verification=verification,
    )


def remediate(
    *,
    run_id: str,
    registry_path: Path,
    evidence_dir: Path | None = None,
    assessments_dir: Path | None = None,
    previous_run_id: str | None = None,
    clock: Callable[[], str] | None = None,
) -> tuple[Path, RemediationDocument]:
    """Compose remediation for one assessed run and write the final report.

    Writes ``remediation.json`` and ``final-report.html`` beside the assessment.
    Neither the assessment nor the evidence it was produced from is modified.
    """
    out_dir = (assessments_dir or ASSESSMENTS_DIR) / run_id
    pre = remediation_preflight(
        registry_path=registry_path,
        assessment_path=out_dir / "assessment.json",
        evidence_path=(evidence_dir or EVIDENCE_DIR) / run_id / "evidence.json",
    )

    previous_assessment = None
    if previous_run_id is not None:
        previous_assessment = load_assessment(
            assessment_path_for(previous_run_id, assessments_dir)
        )

    remediation = build_remediation(
        pre, previous_assessment=previous_assessment, clock=clock
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    document: dict[str, Any] = remediation.model_dump(mode="json", by_alias=True)
    write_json_artifact(out_dir / "remediation.json", document)
    atomic_write_text(
        out_dir / "final-report.html",
        render_final_html(pre.assessment, remediation, remediation.verification),
    )
    return out_dir, remediation


def verify_runs(
    *,
    previous_run_id: str,
    new_run_id: str,
    assessments_dir: Path | None = None,
    clock: Callable[[], str] | None = None,
) -> tuple[Path, VerificationDocument]:
    """Compare two assessments and write the closure decision for the new run."""
    now = clock or _utc_now
    previous = load_assessment(assessment_path_for(previous_run_id, assessments_dir))
    new = load_assessment(assessment_path_for(new_run_id, assessments_dir))

    verification = verify(previous, new, generated_at=now())

    out_dir = (assessments_dir or ASSESSMENTS_DIR) / new_run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    document: dict[str, Any] = verification.model_dump(mode="json", by_alias=True)
    write_json_artifact(out_dir / "verification.json", document)
    return out_dir, verification
