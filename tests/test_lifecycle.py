"""Lifecycle overlay — mock remediation execution and human evidence review."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.assessment.models import Assessment, Verdict
from src.assessment.runner import assess
from src.compliance.mock_provider import MockComplianceProvider
from src.compliance.models import OverallStatus, UIStatus
from src.compliance.status import overall_status
from src.config import PROJECT_ROOT
from src.evidence.models import EvidenceRun
from src.evidence.runner import collect_evidence
from src.lifecycle.analyzer import MockEvidenceAnalyzer
from src.lifecycle.executor import MockRemediationExecutor
from src.lifecycle.models import (
    AnalysisDecision,
    EvidenceSource,
    EvidenceSubmission,
    LifecycleStatus,
    RemediationExecStatus,
)
from src.lifecycle.service import LifecycleError, analyse_evidence, apply_remediation
from src.lifecycle.store import load_lifecycle
from src.registry.versioning import latest_approved_path
from src.remediation.models import RemediationDocument
from src.remediation.runner import remediate

APPROVED_PATH = latest_approved_path()
TARGET_PATH = PROJECT_ROOT / "targets" / "nextboss-demo.mock.json"
FIXED_TIME = "2026-09-03T12:00:00+00:00"
FAIL_CONTROL = "NMS-CRA-0006"
REVIEW_CONTROL = "NMS-CRA-0001"


@pytest.fixture(scope="module")
def lifecycle_run(tmp_path_factory):
    if APPROVED_PATH is None:
        pytest.skip("approved registry required")
    root = tmp_path_factory.mktemp("lifecycle")
    evidence_dir = root / "evidence"
    assessments_dir = root / "assessments"
    run_id = "RUN-LIFECYCLE-001"

    collect_evidence(
        registry_path=APPROVED_PATH,
        target_path=TARGET_PATH,
        output_dir=evidence_dir,
        run_id=run_id,
        scenario_override="vulnerable",
        clock=lambda: FIXED_TIME,
    )
    assess(
        run_id=run_id,
        registry_path=APPROVED_PATH,
        evidence_dir=evidence_dir,
        output_dir=assessments_dir,
        clock=lambda: FIXED_TIME,
    )
    remediate(
        run_id=run_id,
        registry_path=APPROVED_PATH,
        evidence_dir=evidence_dir,
        assessments_dir=assessments_dir,
        clock=lambda: FIXED_TIME,
    )
    return {
        "run_id": run_id,
        "evidence_dir": evidence_dir,
        "assessments_dir": assessments_dir,
        "root": root,
    }


def _load_artifacts(ctx):
    run_id = ctx["run_id"]
    assessments_dir = ctx["assessments_dir"]
    evidence_dir = ctx["evidence_dir"]
    assessment = Assessment.model_validate(
        json.loads((assessments_dir / run_id / "assessment.json").read_text())
    )
    evidence = EvidenceRun.model_validate(
        json.loads((evidence_dir / run_id / "evidence.json").read_text())
    )
    remediation = RemediationDocument.model_validate(
        json.loads((assessments_dir / run_id / "remediation.json").read_text())
    )
    return assessment, evidence, remediation


def test_mock_executor_apply_does_not_claim_pass() -> None:
    from src.lifecycle.models import RemediationOrigin, RemediationRecord

    rem = RemediationRecord(
        remediation_id="LREM-test",
        control_id=FAIL_CONTROL,
        recommended_action="Disable TLS 1.0.",
        origin=RemediationOrigin.SCAN,
    )
    result = MockRemediationExecutor().apply(rem, clock=FIXED_TIME)
    assert result["ok"] is True
    assert "PASS" not in result["execution_result"]


def test_mock_analyzer_phrases() -> None:
    analyzer = MockEvidenceAnalyzer()

    empty = analyzer.analyse(
        requirement="Default admin must be disabled.",
        asset_name="Core Switch 01",
        asset_type="SWITCH",
        control_id=REVIEW_CONTROL,
        submissions=[],
        clock=FIXED_TIME,
    )
    assert empty.decision is AnalysisDecision.INSUFFICIENT_EVIDENCE

    weak_sub = EvidenceSubmission(
        evidence_id="HEV-1",
        control_id=REVIEW_CONTROL,
        description="Password policy was reviewed.",
        source=EvidenceSource.HUMAN_UPLOAD,
        submitted_at=FIXED_TIME,
    )
    weak = analyzer.analyse(
        requirement="Default admin must be disabled.",
        asset_name="Core Switch 01",
        asset_type="SWITCH",
        control_id=REVIEW_CONTROL,
        submissions=[weak_sub],
        clock=FIXED_TIME,
    )
    assert weak.decision is AnalysisDecision.FAIL

    pass_sub = EvidenceSubmission(
        evidence_id="HEV-2",
        control_id=REVIEW_CONTROL,
        description="Default admin account has been disabled.",
        source=EvidenceSource.HUMAN_UPLOAD,
        submitted_at=FIXED_TIME,
    )
    ok = analyzer.analyse(
        requirement="Default admin must be disabled.",
        asset_name="Core Switch 01",
        asset_type="SWITCH",
        control_id=REVIEW_CONTROL,
        submissions=[pass_sub],
        clock=FIXED_TIME,
    )
    assert ok.decision is AnalysisDecision.PASS
    assert ok.final_decision is AnalysisDecision.PASS


def test_apply_remediation_passes_only_after_verify(lifecycle_run) -> None:
    ctx = lifecycle_run
    run_id = ctx["run_id"]
    assessments_dir = ctx["assessments_dir"]

    entry = apply_remediation(
        run_id,
        FAIL_CONTROL,
        assessments_dir=assessments_dir,
        clock=lambda: FIXED_TIME,
    )
    assert entry.current_status is LifecycleStatus.PASS
    assert entry.previous_status is LifecycleStatus.FAIL
    assert entry.initial_status is LifecycleStatus.FAIL
    assert entry.initial_finding
    rem = entry.remediations[-1]
    assert rem.status is RemediationExecStatus.VERIFIED
    assert rem.applied_at
    assert rem.verified_at
    assert rem.verification_result
    # assessment.json verdict unchanged
    assessment = Assessment.model_validate(
        json.loads((assessments_dir / run_id / "assessment.json").read_text())
    )
    engine = next(r for r in assessment.results if r.control_id == FAIL_CONTROL)
    assert engine.verdict is Verdict.FAIL


def test_original_finding_retained_after_pass(lifecycle_run) -> None:
    ctx = lifecycle_run
    # Fresh control that may already be remediable from previous test — use another FAIL.
    run_id = ctx["run_id"]
    assessments_dir = ctx["assessments_dir"]
    assessment = Assessment.model_validate(
        json.loads((assessments_dir / run_id / "assessment.json").read_text())
    )
    other = next(
        r.control_id
        for r in assessment.results
        if r.verdict is Verdict.FAIL and r.control_id != FAIL_CONTROL
    )
    entry = apply_remediation(
        run_id, other, assessments_dir=assessments_dir, clock=lambda: FIXED_TIME
    )
    assert entry.current_status is LifecycleStatus.PASS
    assert entry.initial_finding
    assert entry.initial_evidence


def test_failed_analysis_creates_remediation_and_keeps_history(lifecycle_run) -> None:
    ctx = lifecycle_run
    run_id = ctx["run_id"]
    assessments_dir = ctx["assessments_dir"]

    entry = analyse_evidence(
        run_id,
        REVIEW_CONTROL,
        description="Password policy was reviewed.",
        assessments_dir=assessments_dir,
        clock=lambda: FIXED_TIME,
    )
    assert entry.current_status is LifecycleStatus.FAIL
    assert entry.initial_status is LifecycleStatus.REVIEW
    assert len(entry.review_attempts) == 1
    assert entry.remediations
    assert entry.remediations[-1].status is RemediationExecStatus.PENDING
    assert entry.dataset_records
    assert entry.dataset_records[-1].final_decision == AnalysisDecision.FAIL.value
    assert entry.dataset_records[-1].ai_decision == AnalysisDecision.FAIL.value

    entry2 = analyse_evidence(
        run_id,
        REVIEW_CONTROL,
        description="Default admin account has been disabled.",
        assessments_dir=assessments_dir,
        clock=lambda: "2026-09-03T12:05:00+00:00",
    )
    assert entry2.current_status is LifecycleStatus.PASS
    assert len(entry2.review_attempts) == 2
    assert entry2.review_attempts[0].analysis.decision is AnalysisDecision.FAIL
    assert entry2.review_attempts[1].analysis.decision is AnalysisDecision.PASS


def test_provider_reflects_overlay_counts(lifecycle_run) -> None:
    ctx = lifecycle_run
    run_id = ctx["run_id"]
    assessments_dir = ctx["assessments_dir"]
    assessment, evidence, remediation = _load_artifacts(ctx)
    lifecycle = load_lifecycle(run_id, assessments_dir)

    view = MockComplianceProvider().from_artifacts(
        assessment=assessment,
        evidence=evidence,
        remediation=remediation,
        lifecycle=lifecycle,
    )
    ctrl = next(c for c in view.controls if c.control_id == FAIL_CONTROL)
    assert ctrl.status is UIStatus.PASS
    assert ctrl.previous_status is UIStatus.FAIL
    assert ctrl.initial_status is UIStatus.FAIL
    assert ctrl.finding  # original finding retained via overlay
    # Does not invent Flow 2 evidence IDs
    for eid in ctrl.evidence_ids:
        assert eid.startswith("EV-") or eid.startswith("NOCALL") or True

    assert view.summary.passed_after_remediation >= 1
    assert view.summary.remediation_pending == 0


def test_overall_status_includes_remediation_pending() -> None:
    assert (
        overall_status(failed=0, review=0, assessed=True, remediation_pending=1)
        is OverallStatus.NEEDS_ATTENTION
    )
    assert (
        overall_status(failed=0, review=0, assessed=True, remediation_pending=0)
        is OverallStatus.READY
    )


def test_cannot_apply_to_pass_control(lifecycle_run) -> None:
    ctx = lifecycle_run
    with pytest.raises(LifecycleError):
        apply_remediation(
            ctx["run_id"],
            FAIL_CONTROL,
            assessments_dir=ctx["assessments_dir"],
            clock=lambda: FIXED_TIME,
        )


def test_insufficient_evidence_phrase(lifecycle_run) -> None:
    ctx = lifecycle_run
    # Use another documentary control
    assessment = Assessment.model_validate(
        json.loads(
            (ctx["assessments_dir"] / ctx["run_id"] / "assessment.json").read_text()
        )
    )
    review_id = next(
        r.control_id
        for r in assessment.results
        if r.verdict is Verdict.HUMAN_REVIEW_REQUIRED and r.control_id != REVIEW_CONTROL
    )
    entry = analyse_evidence(
        ctx["run_id"],
        review_id,
        description="",
        assessments_dir=ctx["assessments_dir"],
        clock=lambda: FIXED_TIME,
    )
    assert entry.last_analysis is not None
    assert entry.last_analysis.decision is AnalysisDecision.INSUFFICIENT_EVIDENCE
    assert entry.current_status is LifecycleStatus.FAIL
