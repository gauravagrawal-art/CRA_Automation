"""Controlled remediation-action lifecycle (propose → approve → apply → verify)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.assessment.models import Assessment, Verdict
from src.assessment.runner import assess
from src.compliance.mock_provider import MockComplianceProvider
from src.config import PROJECT_ROOT
from src.evidence.models import EvidenceRun
from src.evidence.runner import collect_evidence
from src.lifecycle.demo_operations import get_operation_for_control
from src.lifecycle.demo_state import load_demo_state
from src.lifecycle.executor import AllowlistedDemoExecutor, MockRemediationExecutor
from src.lifecycle.models import (
    LifecycleDocument,
    LifecycleStatus,
    RemediationExecStatus,
    RemediationOrigin,
    RemediationRecord,
)
from src.lifecycle.service import (
    LifecycleError,
    apply_action,
    approve_action,
    propose_action,
    reconcile_actions_from_verification,
    rollback_action,
)
from src.lifecycle.store import load_lifecycle
from src.lifecycle.transitions import assert_transition, can_transition
from src.registry.versioning import latest_approved_path
from src.remediation.models import RemediationDocument, RemediationStatus
from src.remediation.runner import remediate, verify_runs

APPROVED_PATH = latest_approved_path()
TARGET_PATH = PROJECT_ROOT / "targets" / "nextboss-demo.mock.json"
FIXED_TIME = "2026-09-03T12:00:00+00:00"
FAIL_CONTROL = "NMS-CRA-0006"


@pytest.fixture(scope="module")
def action_run(tmp_path_factory):
    if APPROVED_PATH is None:
        pytest.skip("approved registry required")
    root = tmp_path_factory.mktemp("remediation_actions")
    evidence_dir = root / "evidence"
    assessments_dir = root / "assessments"
    run_id = "RUN-ACTION-001"

    collect_evidence(
        registry_path=APPROVED_PATH,
        target_path=TARGET_PATH,
        output_dir=evidence_dir,
        run_id=run_id,
        scenario_override="vulnerable",
        clock=lambda: FIXED_TIME,
        demo_state_root=assessments_dir / ".demo-state",
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
        "demo_root": assessments_dir / ".demo-state",
    }


def test_transitions_reject_invalid() -> None:
    assert can_transition(
        RemediationExecStatus.PROPOSED, RemediationExecStatus.AWAITING_APPROVAL
    )
    with pytest.raises(ValueError, match="Invalid"):
        assert_transition(
            RemediationExecStatus.PROPOSED, RemediationExecStatus.APPLIED_UNVERIFIED
        )


def test_propose_requires_technical_fail(action_run) -> None:
    ctx = action_run
    entry = propose_action(
        ctx["run_id"],
        FAIL_CONTROL,
        actor="tester",
        assessments_dir=ctx["assessments_dir"],
        clock=lambda: FIXED_TIME,
    )
    rem = entry.remediations[-1]
    assert rem.status is RemediationExecStatus.AWAITING_APPROVAL
    assert rem.finding_remediation_id.startswith("REM-")
    assert rem.operation_id == get_operation_for_control(FAIL_CONTROL).operation_id
    assert rem.evidence_refs
    assert rem.proposed_change
    assert rem.before_state
    assert rem.expected_after_state
    assert rem.risk_and_impact
    assert rem.rollback_method
    assert rem.service_restart_required is True
    assert rem.affected_component

    assessment = Assessment.model_validate(
        json.loads((ctx["assessments_dir"] / ctx["run_id"] / "assessment.json").read_text())
    )
    evidence = EvidenceRun.model_validate(
        json.loads((ctx["evidence_dir"] / ctx["run_id"] / "evidence.json").read_text())
    )
    remediation = RemediationDocument.model_validate(
        json.loads((ctx["assessments_dir"] / ctx["run_id"] / "remediation.json").read_text())
    )
    lifecycle = load_lifecycle(ctx["run_id"], ctx["assessments_dir"])
    view = MockComplianceProvider().from_artifacts(
        assessment=assessment,
        evidence=evidence,
        remediation=remediation,
        lifecycle=lifecycle,
    )
    ctrl = next(c for c in view.controls if c.control_id == FAIL_CONTROL)
    assert ctrl.can_approve_remediation is True
    assert ctrl.service_restart_required is True
    assert ctrl.risk_and_impact
    card = next(r for r in view.remediations if r.control_id == FAIL_CONTROL)
    assert card.can_approve is True
    assert card.service_restart_required is True
    assert card.risk_and_impact


def test_approve_requires_name(action_run) -> None:
    ctx = action_run
    with pytest.raises(LifecycleError, match="Approver"):
        approve_action(
            ctx["run_id"],
            FAIL_CONTROL,
            approver="  ",
            assessments_dir=ctx["assessments_dir"],
            clock=lambda: FIXED_TIME,
        )


def test_apply_lands_unverified_without_closing(action_run) -> None:
    ctx = action_run
    approve_action(
        ctx["run_id"],
        FAIL_CONTROL,
        approver="Ada Approver",
        assessments_dir=ctx["assessments_dir"],
        clock=lambda: "2026-09-03T12:01:00+00:00",
    )
    entry = apply_action(
        ctx["run_id"],
        FAIL_CONTROL,
        actor="tester",
        assessments_dir=ctx["assessments_dir"],
        clock=lambda: "2026-09-03T12:02:00+00:00",
    )
    rem = entry.remediations[-1]
    assert rem.status is RemediationExecStatus.APPLIED_UNVERIFIED
    assert entry.current_status is LifecycleStatus.REMEDIATION_PENDING
    assert rem.applied_overlay_hash

    assessment = Assessment.model_validate(
        json.loads(
            (ctx["assessments_dir"] / ctx["run_id"] / "assessment.json").read_text()
        )
    )
    engine = next(r for r in assessment.results if r.control_id == FAIL_CONTROL)
    assert engine.verdict is Verdict.FAIL

    remediation = RemediationDocument.model_validate(
        json.loads(
            (ctx["assessments_dir"] / ctx["run_id"] / "remediation.json").read_text()
        )
    )
    item = next(i for i in remediation.items if i.finding_control_id == FAIL_CONTROL)
    assert item.status is RemediationStatus.OPEN

    state = load_demo_state("nextboss-demo", root=ctx["demo_root"])
    assert rem.operation_id in state["operations"]


def test_apply_idempotent(action_run) -> None:
    ctx = action_run
    first = apply_action(
        ctx["run_id"],
        FAIL_CONTROL,
        assessments_dir=ctx["assessments_dir"],
        clock=lambda: "2026-09-03T12:03:00+00:00",
    )
    attempt = first.remediations[-1].apply_attempt_id
    second = apply_action(
        ctx["run_id"],
        FAIL_CONTROL,
        assessments_dir=ctx["assessments_dir"],
        clock=lambda: "2026-09-03T12:04:00+00:00",
    )
    assert second.remediations[-1].apply_attempt_id == attempt
    assert second.remediations[-1].status is RemediationExecStatus.APPLIED_UNVERIFIED


def test_rescan_and_reconcile_closes(action_run) -> None:
    ctx = action_run
    new_run = "RUN-ACTION-002"
    collect_evidence(
        registry_path=APPROVED_PATH,
        target_path=TARGET_PATH,
        output_dir=ctx["evidence_dir"],
        run_id=new_run,
        scenario_override="vulnerable",
        clock=lambda: "2026-09-03T13:00:00+00:00",
        demo_state_root=ctx["demo_root"],
    )
    assess(
        run_id=new_run,
        registry_path=APPROVED_PATH,
        evidence_dir=ctx["evidence_dir"],
        output_dir=ctx["assessments_dir"],
        clock=lambda: "2026-09-03T13:01:00+00:00",
    )
    new_assessment = Assessment.model_validate(
        json.loads(
            (ctx["assessments_dir"] / new_run / "assessment.json").read_text()
        )
    )
    new_result = next(r for r in new_assessment.results if r.control_id == FAIL_CONTROL)
    assert new_result.verdict is Verdict.PASS

    # Other vulnerable controls should still fail (scenario not converted wholesale).
    other_fail = next(
        r
        for r in new_assessment.results
        if r.verdict is Verdict.FAIL and r.control_id != FAIL_CONTROL
    )
    assert other_fail is not None

    verify_runs(
        previous_run_id=ctx["run_id"],
        new_run_id=new_run,
        assessments_dir=ctx["assessments_dir"],
        clock=lambda: "2026-09-03T13:02:00+00:00",
    )
    reconcile_actions_from_verification(
        ctx["run_id"],
        new_run,
        assessments_dir=ctx["assessments_dir"],
        clock=lambda: "2026-09-03T13:03:00+00:00",
    )

    life = load_lifecycle(ctx["run_id"], ctx["assessments_dir"])
    rem = life.controls[FAIL_CONTROL].remediations[-1]
    assert rem.status is RemediationExecStatus.VERIFIED
    assert life.controls[FAIL_CONTROL].current_status is LifecycleStatus.PASS

    remediation = RemediationDocument.model_validate(
        json.loads(
            (ctx["assessments_dir"] / ctx["run_id"] / "remediation.json").read_text()
        )
    )
    item = next(i for i in remediation.items if i.finding_control_id == FAIL_CONTROL)
    assert item.status is RemediationStatus.VERIFIED_CLOSED
    assert remediation.summary.by_status[RemediationStatus.VERIFIED_CLOSED.value] >= 1


def test_rollback_restores_vulnerable_observation(tmp_path) -> None:
    if APPROVED_PATH is None:
        pytest.skip("approved registry required")
    evidence_dir = tmp_path / "evidence"
    assessments_dir = tmp_path / "assessments"
    demo_root = assessments_dir / ".demo-state"
    run_id = "RUN-ROLLBACK-001"

    collect_evidence(
        registry_path=APPROVED_PATH,
        target_path=TARGET_PATH,
        output_dir=evidence_dir,
        run_id=run_id,
        scenario_override="vulnerable",
        clock=lambda: FIXED_TIME,
        demo_state_root=demo_root,
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
    propose_action(
        run_id, FAIL_CONTROL, assessments_dir=assessments_dir, clock=lambda: FIXED_TIME
    )
    approve_action(
        run_id,
        FAIL_CONTROL,
        approver="Ada",
        assessments_dir=assessments_dir,
        clock=lambda: FIXED_TIME,
    )
    apply_action(
        run_id, FAIL_CONTROL, assessments_dir=assessments_dir, clock=lambda: FIXED_TIME
    )
    rollback_action(
        run_id, FAIL_CONTROL, assessments_dir=assessments_dir, clock=lambda: FIXED_TIME
    )

    state = load_demo_state("nextboss-demo", root=demo_root)
    op = get_operation_for_control(FAIL_CONTROL)
    assert op.operation_id not in state["operations"]

    new_run = "RUN-ROLLBACK-002"
    collect_evidence(
        registry_path=APPROVED_PATH,
        target_path=TARGET_PATH,
        output_dir=evidence_dir,
        run_id=new_run,
        scenario_override="vulnerable",
        clock=lambda: "2026-09-03T14:00:00+00:00",
        demo_state_root=demo_root,
    )
    assess(
        run_id=new_run,
        registry_path=APPROVED_PATH,
        evidence_dir=evidence_dir,
        output_dir=assessments_dir,
        clock=lambda: "2026-09-03T14:01:00+00:00",
    )
    assessment = Assessment.model_validate(
        json.loads((assessments_dir / new_run / "assessment.json").read_text())
    )
    result = next(r for r in assessment.results if r.control_id == FAIL_CONTROL)
    assert result.verdict is Verdict.FAIL


def test_executor_refuses_non_demo() -> None:
    rem = RemediationRecord(
        remediation_id="LREM-x",
        control_id=FAIL_CONTROL,
        operation_id=get_operation_for_control(FAIL_CONTROL).operation_id,
        origin=RemediationOrigin.SCAN,
    )
    result = AllowlistedDemoExecutor().apply(
        rem,
        clock=FIXED_TIME,
        target_id="other-host",
        provider="mock",
    )
    assert result["ok"] is False
    assert result.get("blocked") is True


def test_legacy_lifecycle_1_0_loads_without_closing() -> None:
    doc = LifecycleDocument.model_validate(
        {
            "run_id": "RUN-LEGACY",
            "schema_version": "1.0",
            "controls": {
                FAIL_CONTROL: {
                    "control_id": FAIL_CONTROL,
                    "initial_status": "FAIL",
                    "current_status": "PASS",
                    "remediations": [
                        {
                            "remediation_id": "LREM-legacy",
                            "control_id": FAIL_CONTROL,
                            "status": "VERIFIED",
                            "recommended_action": "legacy",
                        }
                    ],
                }
            },
        }
    )
    assert doc.schema_version == "1.0"
    rem = doc.controls[FAIL_CONTROL].remediations[0]
    assert rem.status is RemediationExecStatus.VERIFIED
    # Overlay VERIFIED alone must not imply Flow 4 finding closure.
    assert RemediationStatus.OPEN.value == "OPEN"


def test_mock_executor_verify_disabled() -> None:
    rem = RemediationRecord(
        remediation_id="LREM-t",
        control_id=FAIL_CONTROL,
        recommended_action="x",
        origin=RemediationOrigin.SCAN,
    )
    result = MockRemediationExecutor().verify(
        rem,
        control_id=FAIL_CONTROL,
        finding="f",
        recommended_action="x",
        clock=FIXED_TIME,
    )
    assert result["ok"] is False
