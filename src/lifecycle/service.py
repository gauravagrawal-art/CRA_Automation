"""Orchestrate remediation-action lifecycle and human evidence analysis.

Domain rules enforced here:
- Suggested remediation != PASS / finding closure
- Apply never mutates assessment.json or closes Flow 4 findings
- Closure requires Flow 4 verify + reconcile after a fresh evidence run
- Uploaded evidence != PASS until analysis accepts it
- Original findings are retained on ControlLifecycle
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from src.assessment.models import Assessment, Verdict
from src.compliance.applicability import mock_assets, primary_asset
from src.compliance.content import evidence_facts, index_evidence, short_finding, short_requirement
from src.compliance.models import UIStatus
from src.compliance.status import map_verdict
from src.config import (
    ASSESSMENTS_DIR,
    DEMO_PROVIDER,
    DEMO_TARGET_ID,
    HUMAN_EVIDENCE_MAX_BYTES,
    LIFECYCLE_SCHEMA_VERSION,
)
from src.evidence.models import EvidenceRun
from src.lifecycle.analyzer import get_evidence_analyzer
from src.lifecycle.demo_operations import get_operation_for_control
from src.lifecycle.demo_state import assessments_demo_root
from src.lifecycle.executor import get_remediation_executor
from src.lifecycle.models import (
    AnalysisDecision,
    ApprovalAction,
    ControlLifecycle,
    DatasetRecord,
    EvidenceAttachment,
    EvidenceSource,
    EvidenceSubmission,
    LifecycleDocument,
    LifecycleStatus,
    RemediationExecStatus,
    RemediationOrigin,
    RemediationRecord,
    ReviewAttempt,
    RollbackEvent,
    StatusHistoryEntry,
    ValidationResultEntry,
    make_apply_attempt_id,
    make_evidence_id,
    make_remediation_id,
)
from src.lifecycle.store import human_evidence_dir, load_lifecycle, save_lifecycle
from src.lifecycle.transitions import assert_transition
from src.remediation.models import (
    ActionType,
    RemediationDocument,
    RemediationStatus,
    VerificationDocument,
    VerificationOutcome,
    summarize,
)
from src.services import runs_service

Clock = Callable[[], str]


class LifecycleError(RuntimeError):
    """User-facing refusal before or during a lifecycle action."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_assessment(run_id: str, assessments_dir: Path | None) -> Assessment | None:
    if assessments_dir is not None:
        path = assessments_dir / run_id / "assessment.json"
        if not path.exists():
            return None
        return Assessment.model_validate(json.loads(path.read_text(encoding="utf-8")))
    return runs_service.load_assessment(run_id)


def _load_remediation_doc(
    run_id: str, assessments_dir: Path | None
) -> RemediationDocument | None:
    if assessments_dir is not None:
        path = assessments_dir / run_id / "remediation.json"
        if not path.exists():
            return None
        return RemediationDocument.model_validate(
            json.loads(path.read_text(encoding="utf-8"))
        )
    return runs_service.load_remediation(run_id)


def _save_remediation_doc(
    document: RemediationDocument,
    assessments_dir: Path | None,
) -> None:
    root = assessments_dir or ASSESSMENTS_DIR
    path = root / document.metadata.run_id / "remediation.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _load_evidence_run(run_id: str, assessments_dir: Path | None) -> EvidenceRun | None:
    if assessments_dir is not None:
        candidate = assessments_dir.parent / "evidence" / run_id / "evidence.json"
        if candidate.exists():
            return EvidenceRun.model_validate(
                json.loads(candidate.read_text(encoding="utf-8"))
            )
        return None
    return runs_service.load_evidence(run_id)


def _load_verification(
    run_id: str, assessments_dir: Path | None
) -> VerificationDocument | None:
    if assessments_dir is not None:
        path = assessments_dir / run_id / "verification.json"
        if path.exists():
            return VerificationDocument.model_validate(
                json.loads(path.read_text(encoding="utf-8"))
            )
        rem = _load_remediation_doc(run_id, assessments_dir)
        return rem.verification if rem else None
    verification = runs_service.load_verification(run_id)
    if verification is not None:
        return verification
    rem = runs_service.load_remediation(run_id)
    return rem.verification if rem else None


def _to_lifecycle_status(ui: UIStatus) -> LifecycleStatus:
    if ui is UIStatus.PASS:
        return LifecycleStatus.PASS
    if ui is UIStatus.FAIL:
        return LifecycleStatus.FAIL
    if ui is UIStatus.NOT_APPLICABLE:
        return LifecycleStatus.NOT_APPLICABLE
    if ui is UIStatus.REMEDIATION_PENDING:
        return LifecycleStatus.REMEDIATION_PENDING
    return LifecycleStatus.REVIEW


def _ui_from_lifecycle(status: LifecycleStatus) -> UIStatus:
    return UIStatus(status.value)


def _ensure_document(
    run_id: str,
    *,
    assessment: Assessment,
    assessments_dir: Path | None,
    clock: str,
) -> LifecycleDocument:
    doc = load_lifecycle(run_id, assessments_dir)
    if doc is not None:
        return doc
    return LifecycleDocument(
        run_id=run_id,
        assessment_id=assessment.metadata.assessment_id,
        schema_version=LIFECYCLE_SCHEMA_VERSION,
        generated_at=clock,
        updated_at=clock,
        controls={},
    )


def _control_result(assessment: Assessment, control_id: str):
    for result in assessment.results:
        if result.control_id == control_id:
            return result
    raise LifecycleError(
        f"Control '{control_id}' was not assessed in run {assessment.metadata.run_id}."
    )


def _asset_for_control(control_id: str, result, registry: dict | None) -> tuple[str, str, str]:
    assets = mock_assets()
    control_meta = {"control_id": control_id, "title": result.title}
    if registry:
        for c in registry.get("controls") or []:
            if c.get("control_id") == control_id:
                control_meta = c
                break
    status = map_verdict(result.verdict)
    primary = primary_asset(
        control_meta,
        assets,
        status_is_fail=status is UIStatus.FAIL,
    )
    if primary is None and assets:
        primary = assets[0]
    if primary is None:
        return "", "", ""
    return primary.asset_id, primary.name, primary.type.value


def _registry_dict() -> dict | None:
    try:
        from src.services.registry_service import load_approved

        return load_approved().model_dump(mode="json")
    except Exception:
        return None


def _ensure_control(
    doc: LifecycleDocument,
    *,
    assessment: Assessment,
    control_id: str,
    clock: str,
    assessments_dir: Path | None = None,
) -> ControlLifecycle:
    if control_id in doc.controls:
        return doc.controls[control_id]

    result = _control_result(assessment, control_id)
    evidence = _load_evidence_run(assessment.metadata.run_id, assessments_dir)
    evidence_by_id = index_evidence(evidence)
    status = _to_lifecycle_status(map_verdict(result.verdict))
    facts = evidence_facts(result, evidence_by_id)
    finding = short_finding(result, map_verdict(result.verdict), facts)
    asset_id, _, _ = _asset_for_control(control_id, result, _registry_dict())

    entry = ControlLifecycle(
        control_id=control_id,
        asset_id=asset_id,
        initial_status=status,
        current_status=status,
        previous_status=None,
        initial_finding=finding or result.reason or result.observed_state,
        initial_evidence=[f.text for f in facts] or list(result.evidence_ids),
        updated_at=clock,
    )
    doc.controls[control_id] = entry
    return entry


def _active_remediation(entry: ControlLifecycle) -> RemediationRecord | None:
    for rem in reversed(entry.remediations):
        if rem.status not in (
            RemediationExecStatus.VERIFIED,
            RemediationExecStatus.NOT_REQUIRED,
            RemediationExecStatus.ROLLED_BACK,
        ):
            return rem
    return entry.remediations[-1] if entry.remediations else None


def _flow4_item(
    remediation_doc: RemediationDocument | None, control_id: str
):
    if remediation_doc is None:
        return None
    for item in remediation_doc.items:
        if item.finding_control_id == control_id:
            return item
    return None


def _record_transition(
    rem: RemediationRecord,
    target: RemediationExecStatus,
    *,
    clock: str,
    actor: str,
    reason: str = "",
) -> None:
    assert_transition(rem.status, target)
    if rem.status is target:
        return
    rem.status_history.append(
        StatusHistoryEntry(
            **{
                "from": rem.status.value,
                "to": target.value,
                "at": clock,
                "actor": actor,
                "reason": reason,
            }
        )
    )
    rem.status = target
    rem.actor = actor or rem.actor


def propose_action(
    run_id: str,
    control_id: str,
    *,
    actor: str = "operator",
    assessments_dir: Path | None = None,
    clock: Clock | None = None,
) -> ControlLifecycle:
    """Create a remediation proposal from an eligible failed finding and submit it."""
    now = (clock or _utc_now)()
    root = assessments_dir or ASSESSMENTS_DIR
    assessment = _load_assessment(run_id, assessments_dir)
    if assessment is None:
        raise LifecycleError(f"No assessment for run {run_id}.")

    remediation_doc = _load_remediation_doc(run_id, assessments_dir)
    item = _flow4_item(remediation_doc, control_id)
    if item is None:
        raise LifecycleError(
            f"No Flow 4 remediation item for {control_id}. Compose remediation first."
        )
    if item.action_type is not ActionType.TECHNICAL_REMEDIATION:
        raise LifecycleError(
            f"Only TECHNICAL_REMEDIATION findings are eligible (got {item.action_type.value})."
        )
    if item.status is not RemediationStatus.OPEN:
        raise LifecycleError(
            f"Finding {control_id} is {item.status.value}; only OPEN findings may be proposed."
        )

    result = _control_result(assessment, control_id)
    if result.verdict not in (Verdict.FAIL, Verdict.PARTIAL):
        raise LifecycleError(
            f"Propose is only available for FAIL/PARTIAL controls (got {result.verdict.value})."
        )

    operation = get_operation_for_control(control_id)
    doc = _ensure_document(
        run_id, assessment=assessment, assessments_dir=assessments_dir, clock=now
    )
    entry = _ensure_control(
        doc,
        assessment=assessment,
        control_id=control_id,
        clock=now,
        assessments_dir=assessments_dir,
    )
    if entry.current_status is LifecycleStatus.PASS:
        raise LifecycleError(f"Control {control_id} already passed.")

    rem = _active_remediation(entry)
    if rem is not None and rem.status in (
        RemediationExecStatus.AWAITING_APPROVAL,
        RemediationExecStatus.APPROVED,
        RemediationExecStatus.APPLYING,
        RemediationExecStatus.APPLIED_UNVERIFIED,
    ):
        raise LifecycleError(
            f"An active remediation action already exists in status {rem.status.value}."
        )

    action = (item.recommendation or "").strip()
    if not action:
        raise LifecycleError(f"No approved remediation recommendation for {control_id}.")

    rem = RemediationRecord(
        remediation_id=make_remediation_id(run_id, control_id, RemediationOrigin.SCAN),
        control_id=control_id,
        asset_id=entry.asset_id,
        issue=item.observed_state or entry.initial_finding,
        recommended_action=action,
        verification_method=(
            operation.validation_method
            if operation
            else "Fresh evidence collection and deterministic assessment"
        ),
        status=RemediationExecStatus.PROPOSED,
        created_at=now,
        origin=RemediationOrigin.SCAN,
        finding_remediation_id=item.remediation_id,
        target_id=assessment.metadata.target_id,
        registry_hash=assessment.metadata.registry_hash,
        operation_id=operation.operation_id if operation else "",
        observed_evidence=item.observed_state or result.observed_state or "",
        evidence_refs=list(item.evidence_ids or result.evidence_ids),
        proposed_change=operation.proposed_change if operation else action,
        before_state=operation.before_state if operation else (item.observed_state or ""),
        expected_after_state=(
            operation.expected_after_state
            if operation
            else "Control returns PASS under the same approved baseline."
        ),
        change_reason=operation.change_reason if operation else item.reason,
        affected_component=(
            operation.affected_component if operation else "target configuration"
        ),
        service_restart_required=bool(
            operation.service_restart_required if operation else False
        ),
        risk_and_impact=(
            operation.risk_and_impact
            if operation
            else "Configuration change may affect management-plane access."
        ),
        validation_method=(
            operation.validation_method
            if operation
            else "Re-scan and verify with Flow 2 + Flow 3 + Flow 4 verify."
        ),
        rollback_method=(
            operation.rollback_method
            if operation
            else "Revert the change outside this application and re-scan."
        ),
        actor=actor,
    )
    rem.status_history.append(
        StatusHistoryEntry(
            **{
                "from": RemediationExecStatus.PROPOSED.value,
                "to": RemediationExecStatus.PROPOSED.value,
                "at": now,
                "actor": actor,
                "reason": "Proposal created",
            }
        )
    )
    _record_transition(
        rem,
        RemediationExecStatus.AWAITING_APPROVAL,
        clock=now,
        actor=actor,
        reason="Submitted for approval",
    )
    entry.remediations.append(rem)
    entry.updated_at = now
    doc.schema_version = LIFECYCLE_SCHEMA_VERSION
    doc.updated_at = now
    save_lifecycle(doc, root)
    return entry


def approve_action(
    run_id: str,
    control_id: str,
    *,
    approver: str,
    action: ApprovalAction | str = ApprovalAction.APPROVE,
    assessments_dir: Path | None = None,
    clock: Clock | None = None,
) -> ControlLifecycle:
    """Approve or reject a proposed remediation action."""
    now = (clock or _utc_now)()
    root = assessments_dir or ASSESSMENTS_DIR
    approver_name = (approver or "").strip()
    if not approver_name:
        raise LifecycleError("Approver name is required.")

    if isinstance(action, str):
        try:
            action = ApprovalAction(action.upper())
        except ValueError as exc:
            raise LifecycleError("Approval action must be APPROVE or REJECT.") from exc

    assessment = _load_assessment(run_id, assessments_dir)
    if assessment is None:
        raise LifecycleError(f"No assessment for run {run_id}.")

    doc = load_lifecycle(run_id, assessments_dir)
    if doc is None or control_id not in doc.controls:
        raise LifecycleError(f"No remediation proposal for {control_id}.")
    entry = doc.controls[control_id]
    rem = _active_remediation(entry)
    if rem is None:
        raise LifecycleError(f"No remediation action for {control_id}.")
    if rem.status is not RemediationExecStatus.AWAITING_APPROVAL:
        raise LifecycleError(
            f"Action is {rem.status.value}; expected AWAITING_APPROVAL."
        )

    rem.approver = approver_name
    rem.approved_at = now
    rem.approval_action = action
    if action is ApprovalAction.APPROVE:
        _record_transition(
            rem,
            RemediationExecStatus.APPROVED,
            clock=now,
            actor=approver_name,
            reason="Explicit approval",
        )
    else:
        _record_transition(
            rem,
            RemediationExecStatus.PROPOSED,
            clock=now,
            actor=approver_name,
            reason="Rejected; returned to proposal",
        )
    entry.updated_at = now
    doc.updated_at = now
    save_lifecycle(doc, root)
    return entry


def apply_action(
    run_id: str,
    control_id: str,
    *,
    actor: str = "operator",
    assessments_dir: Path | None = None,
    clock: Clock | None = None,
) -> ControlLifecycle:
    """Apply an approved action on the demo target. Does not close the finding."""
    now = (clock or _utc_now)()
    root = assessments_dir or ASSESSMENTS_DIR
    assessment = _load_assessment(run_id, assessments_dir)
    if assessment is None:
        raise LifecycleError(f"No assessment for run {run_id}.")

    doc = load_lifecycle(run_id, assessments_dir)
    if doc is None or control_id not in doc.controls:
        raise LifecycleError(f"No remediation action for {control_id}. Propose first.")
    entry = doc.controls[control_id]
    rem = _active_remediation(entry)
    if rem is None:
        raise LifecycleError(f"No remediation action for {control_id}.")

    # Idempotent: already applying / applied / verified — return as-is.
    if rem.status in (
        RemediationExecStatus.APPLYING,
        RemediationExecStatus.APPLIED_UNVERIFIED,
        RemediationExecStatus.VERIFIED,
    ):
        return entry

    if rem.status is RemediationExecStatus.BLOCKED:
        # Allow retry only via approve path; apply from BLOCKED is refused.
        raise LifecycleError(
            rem.failure_reason
            or "Action is BLOCKED. Clear the block (re-approve on an executable target)."
        )

    if rem.status is not RemediationExecStatus.APPROVED:
        raise LifecycleError(
            f"Apply requires APPROVED status (got {rem.status.value})."
        )

    target_id = assessment.metadata.target_id
    provider = assessment.metadata.provider
    demo_root = assessments_demo_root(assessments_dir)

    if target_id != DEMO_TARGET_ID or provider != DEMO_PROVIDER:
        rem.failure_reason = (
            f"Execution is allow-listed only for {DEMO_TARGET_ID} ({DEMO_PROVIDER})."
        )
        _record_transition(
            rem,
            RemediationExecStatus.BLOCKED,
            clock=now,
            actor=actor,
            reason=rem.failure_reason,
        )
        entry.updated_at = now
        doc.updated_at = now
        save_lifecycle(doc, root)
        raise LifecycleError(rem.failure_reason)

    if not rem.operation_id or get_operation_for_control(control_id) is None:
        rem.failure_reason = f"No allow-listed demo operation for {control_id}."
        _record_transition(
            rem,
            RemediationExecStatus.BLOCKED,
            clock=now,
            actor=actor,
            reason=rem.failure_reason,
        )
        entry.updated_at = now
        doc.updated_at = now
        save_lifecycle(doc, root)
        raise LifecycleError(rem.failure_reason)

    rem.apply_attempt_id = make_apply_attempt_id(rem.remediation_id, now)
    _record_transition(
        rem,
        RemediationExecStatus.APPLYING,
        clock=now,
        actor=actor,
        reason="Apply started",
    )
    entry.previous_status = entry.current_status
    entry.current_status = LifecycleStatus.REMEDIATION_PENDING
    entry.updated_at = now
    doc.updated_at = now
    save_lifecycle(doc, root)  # persist APPLYING before executor

    executor = get_remediation_executor()
    apply_result = executor.apply(
        rem,
        clock=now,
        target_id=target_id,
        provider=provider,
        demo_state_root=demo_root,
    )

    if not apply_result.get("ok"):
        rem.failure_reason = str(apply_result.get("execution_result") or "Apply failed.")
        rem.execution_result = rem.failure_reason
        _record_transition(
            rem,
            RemediationExecStatus.FAILED,
            clock=now,
            actor=actor,
            reason=rem.failure_reason,
        )
        entry.current_status = LifecycleStatus.FAIL
        doc.updated_at = now
        save_lifecycle(doc, root)
        raise LifecycleError(rem.failure_reason)

    rem.execution_result = str(apply_result.get("execution_result") or "")
    rem.applied_at = str(apply_result.get("applied_at") or now)
    rem.applied_overlay_hash = str(apply_result.get("applied_overlay_hash") or "")
    _record_transition(
        rem,
        RemediationExecStatus.APPLIED_UNVERIFIED,
        clock=now,
        actor=actor,
        reason="Applied on demo target; awaiting re-scan",
    )
    entry.current_status = LifecycleStatus.REMEDIATION_PENDING
    entry.updated_at = now
    doc.updated_at = now
    save_lifecycle(doc, root)
    return entry


def apply_remediation(
    run_id: str,
    control_id: str,
    *,
    assessments_dir: Path | None = None,
    clock: Clock | None = None,
    actor: str = "operator",
) -> ControlLifecycle:
    """Backward-compatible entry: apply an already-approved action only."""
    return apply_action(
        run_id,
        control_id,
        actor=actor,
        assessments_dir=assessments_dir,
        clock=clock,
    )


def rollback_action(
    run_id: str,
    control_id: str,
    *,
    actor: str = "operator",
    assessments_dir: Path | None = None,
    clock: Clock | None = None,
) -> ControlLifecycle:
    """Roll back a demo overlay operation; finding stays OPEN."""
    now = (clock or _utc_now)()
    root = assessments_dir or ASSESSMENTS_DIR
    assessment = _load_assessment(run_id, assessments_dir)
    if assessment is None:
        raise LifecycleError(f"No assessment for run {run_id}.")

    doc = load_lifecycle(run_id, assessments_dir)
    if doc is None or control_id not in doc.controls:
        raise LifecycleError(f"No remediation action for {control_id}.")
    entry = doc.controls[control_id]
    rem = _active_remediation(entry)
    if rem is None:
        raise LifecycleError(f"No remediation action for {control_id}.")
    if rem.status not in (
        RemediationExecStatus.APPLIED_UNVERIFIED,
        RemediationExecStatus.FAILED,
    ):
        raise LifecycleError(
            f"Rollback requires APPLIED_UNVERIFIED or FAILED (got {rem.status.value})."
        )

    executor = get_remediation_executor()
    result = executor.rollback(
        rem,
        clock=now,
        target_id=assessment.metadata.target_id,
        provider=assessment.metadata.provider,
        demo_state_root=assessments_demo_root(assessments_dir),
    )
    message = str(result.get("execution_result") or "Rolled back.")
    rem.rollback_events.append(
        RollbackEvent(at=now, actor=actor, reason="Operator rollback", result=message)
    )
    if not result.get("ok"):
        rem.failure_reason = message
        raise LifecycleError(message)

    _record_transition(
        rem,
        RemediationExecStatus.ROLLED_BACK,
        clock=now,
        actor=actor,
        reason=message,
    )
    entry.previous_status = entry.current_status
    entry.current_status = LifecycleStatus.FAIL
    entry.updated_at = now
    doc.updated_at = now
    save_lifecycle(doc, root)
    return entry


def reconcile_actions_from_verification(
    previous_run_id: str,
    new_run_id: str,
    *,
    assessments_dir: Path | None = None,
    clock: Clock | None = None,
    actor: str = "verifier",
) -> None:
    """Update origin actions and Flow 4 finding status from a verification document.

    Does not re-run verify(); reads the existing verification artifact.
    """
    now = (clock or _utc_now)()
    root = assessments_dir or ASSESSMENTS_DIR
    verification = _load_verification(new_run_id, assessments_dir)
    if verification is None:
        return

    origin_doc = load_lifecycle(previous_run_id, assessments_dir)
    remediation = _load_remediation_doc(previous_run_id, assessments_dir)

    for vitem in verification.items:
        control_id = vitem.control_id
        rem_record = None
        entry = None
        if origin_doc is not None and control_id in origin_doc.controls:
            entry = origin_doc.controls[control_id]
            for candidate in reversed(entry.remediations):
                if candidate.status in (
                    RemediationExecStatus.APPLIED_UNVERIFIED,
                    RemediationExecStatus.FAILED,
                    RemediationExecStatus.BLOCKED,
                    RemediationExecStatus.APPLYING,
                ):
                    rem_record = candidate
                    break

        if rem_record is not None and entry is not None:
            rem_record.verification_run_id = new_run_id
            rem_record.verification_outcome = vitem.outcome.value
            rem_record.validation_results.append(
                ValidationResultEntry(
                    at=now,
                    ok=vitem.outcome is VerificationOutcome.VERIFIED_CLOSED,
                    message=vitem.reason,
                    run_id=new_run_id,
                )
            )
            if vitem.outcome is VerificationOutcome.VERIFIED_CLOSED:
                if rem_record.status is not RemediationExecStatus.VERIFIED:
                    try:
                        if rem_record.status is RemediationExecStatus.APPLYING:
                            _record_transition(
                                rem_record,
                                RemediationExecStatus.APPLIED_UNVERIFIED,
                                clock=now,
                                actor=actor,
                                reason="Normalized before verify reconcile",
                            )
                        _record_transition(
                            rem_record,
                            RemediationExecStatus.VERIFIED,
                            clock=now,
                            actor=actor,
                            reason=vitem.reason,
                        )
                    except ValueError:
                        rem_record.status = RemediationExecStatus.VERIFIED
                rem_record.verified_at = now
                rem_record.verification_result = vitem.reason
                entry.previous_status = entry.current_status
                entry.current_status = LifecycleStatus.PASS
            elif vitem.outcome is VerificationOutcome.VERIFICATION_BLOCKED:
                rem_record.failure_reason = vitem.reason
                try:
                    _record_transition(
                        rem_record,
                        RemediationExecStatus.BLOCKED,
                        clock=now,
                        actor=actor,
                        reason=vitem.reason,
                    )
                except ValueError:
                    rem_record.status = RemediationExecStatus.BLOCKED
                entry.current_status = LifecycleStatus.FAIL
            else:
                rem_record.failure_reason = vitem.reason
                try:
                    if rem_record.status is RemediationExecStatus.APPLIED_UNVERIFIED:
                        _record_transition(
                            rem_record,
                            RemediationExecStatus.FAILED,
                            clock=now,
                            actor=actor,
                            reason=vitem.reason,
                        )
                    elif rem_record.status is RemediationExecStatus.APPLYING:
                        _record_transition(
                            rem_record,
                            RemediationExecStatus.FAILED,
                            clock=now,
                            actor=actor,
                            reason=vitem.reason,
                        )
                except ValueError:
                    rem_record.status = RemediationExecStatus.FAILED
                entry.current_status = LifecycleStatus.FAIL
            entry.updated_at = now

        if remediation is not None and vitem.outcome is VerificationOutcome.VERIFIED_CLOSED:
            for item in remediation.items:
                if item.finding_control_id == control_id:
                    item.status = RemediationStatus.VERIFIED_CLOSED

    if origin_doc is not None:
        origin_doc.updated_at = now
        save_lifecycle(origin_doc, root)

    if remediation is not None:
        remediation.summary = summarize(
            remediation.items, remediation.summary.controls_assessed
        )
        _save_remediation_doc(remediation, assessments_dir)


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _sanitize_filename(name: str) -> str:
    base = Path(name).name
    cleaned = _SAFE_NAME.sub("_", base).strip("._") or "upload.bin"
    return cleaned[:120]


def analyse_evidence(
    run_id: str,
    control_id: str,
    *,
    description: str = "",
    comments: str = "",
    files: list[tuple[str, bytes, str]] | None = None,
    submitted_by: str = "reviewer",
    assessments_dir: Path | None = None,
    clock: Clock | None = None,
) -> ControlLifecycle:
    """Submit human evidence, run MOCK analyser, update overlay status."""
    now = (clock or _utc_now)()
    root = assessments_dir or ASSESSMENTS_DIR
    assessment = _load_assessment(run_id, assessments_dir)
    if assessment is None:
        raise LifecycleError(f"No assessment for run {run_id}.")

    result = _control_result(assessment, control_id)
    initial_ui = map_verdict(result.verdict)
    if initial_ui is not UIStatus.REVIEW:
        raise LifecycleError(
            "Evidence analysis is only available for human-review controls."
        )

    doc = _ensure_document(
        run_id, assessment=assessment, assessments_dir=assessments_dir, clock=now
    )
    entry = _ensure_control(
        doc,
        assessment=assessment,
        control_id=control_id,
        clock=now,
        assessments_dir=assessments_dir,
    )

    if entry.current_status is LifecycleStatus.PASS:
        raise LifecycleError(f"Control {control_id} already passed.")

    if entry.current_status not in (
        LifecycleStatus.REVIEW,
        LifecycleStatus.FAIL,
        LifecycleStatus.REMEDIATION_PENDING,
    ):
        raise LifecycleError(
            f"Cannot submit evidence for control in status {entry.current_status.value}."
        )

    attempt_no = len(entry.review_attempts) + 1
    evidence_id = make_evidence_id(run_id, control_id, attempt_no)
    attachments: list[EvidenceAttachment] = []
    upload_root = human_evidence_dir(run_id, root) / control_id
    upload_root.mkdir(parents=True, exist_ok=True)

    for filename, content, content_type in files or []:
        if len(content) > HUMAN_EVIDENCE_MAX_BYTES:
            raise LifecycleError(
                f"Attachment '{filename}' exceeds {HUMAN_EVIDENCE_MAX_BYTES} bytes."
            )
        safe = _sanitize_filename(filename)
        stored = upload_root / f"{attempt_no}_{safe}"
        stored.write_bytes(content)
        try:
            rel = str(stored.relative_to(root))
        except ValueError:
            rel = str(stored)
        attachments.append(
            EvidenceAttachment(
                filename=safe,
                stored_path=rel,
                size_bytes=len(content),
                content_type=content_type or "application/octet-stream",
            )
        )

    submission = EvidenceSubmission(
        evidence_id=evidence_id,
        control_id=control_id,
        asset_id=entry.asset_id,
        description=(description or "").strip(),
        attachments=attachments,
        comments=(comments or "").strip(),
        source=EvidenceSource.HUMAN_UPLOAD,
        submitted_by=submitted_by,
        submitted_at=now,
    )
    entry.evidence_submissions.append(submission)

    asset_id, asset_name, asset_type = _asset_for_control(
        control_id, result, _registry_dict()
    )
    if asset_id and not entry.asset_id:
        entry.asset_id = asset_id

    analyzer = get_evidence_analyzer()
    analysis = analyzer.analyse(
        requirement=short_requirement(result),
        asset_name=asset_name,
        asset_type=asset_type,
        control_id=control_id,
        submissions=entry.evidence_submissions,
        clock=now,
    )
    final = analysis.resolve_final()
    analysis.final_decision = final
    entry.last_analysis = analysis
    entry.review_attempts.append(
        ReviewAttempt(
            attempt=attempt_no,
            submission=submission,
            analysis=analysis,
            timestamp=now,
        )
    )

    entry.previous_status = entry.current_status
    rem_text = ""
    ver_text = ""

    if final is AnalysisDecision.PASS:
        entry.current_status = LifecycleStatus.PASS
        ver_text = analysis.evidence_summary
    else:
        entry.current_status = LifecycleStatus.FAIL
        req = short_requirement(result).lower()
        title = (result.title or "").lower()
        if "admin" in title or "credential" in req or "default" in req:
            rem_text = (
                "Disable the default administrator account and provide "
                "configuration evidence confirming the change."
            )
        else:
            rem_text = (
                "Address the control requirement and provide configuration evidence "
                f"confirming the change. ({analysis.reason})"
            )
        rem = _active_remediation(entry)
        if rem is None or rem.status is RemediationExecStatus.VERIFIED:
            rem = RemediationRecord(
                remediation_id=make_remediation_id(
                    run_id, control_id, RemediationOrigin.HUMAN_REVIEW
                ),
                control_id=control_id,
                asset_id=entry.asset_id,
                issue=analysis.reason,
                recommended_action=rem_text,
                verification_method="Human evidence re-submission or mock remediation",
                status=RemediationExecStatus.PENDING,
                created_at=now,
                origin=RemediationOrigin.HUMAN_REVIEW,
            )
            entry.remediations.append(rem)
        else:
            rem.issue = analysis.reason
            rem.recommended_action = rem_text
            rem.status = RemediationExecStatus.PENDING

    entry.dataset_records.append(
        DatasetRecord(
            control_id=control_id,
            control_requirement=short_requirement(result),
            asset_type=asset_type,
            evidence=submission.description
            or ", ".join(a.filename for a in submission.attachments),
            human_decision="",
            ai_decision=(analysis.ai_decision or analysis.decision).value,
            final_decision=final.value,
            decision_reason=analysis.reason,
            remediation=rem_text,
            verification_result=ver_text,
            recorded_at=now,
        )
    )
    entry.updated_at = now
    doc.updated_at = now
    save_lifecycle(doc, root)
    return entry


def refresh_reports(run_id: str, *, assessments_dir: Path | None = None) -> None:
    """Rewrite HTML reports so downloads include overlay outcomes."""
    from src.assessment.report import render_html
    from src.remediation.report import render_final_html
    from src.services.runs_service import final_report_path, report_path

    root = assessments_dir or ASSESSMENTS_DIR
    assessment = _load_assessment(run_id, assessments_dir)
    if assessment is None:
        return

    html = render_html(assessment, assessments_dir=assessments_dir)
    report_path(run_id, root).write_text(html, encoding="utf-8")

    remediation = _load_remediation_doc(run_id, assessments_dir)
    if remediation is not None:
        final = render_final_html(
            assessment,
            remediation,
            remediation.verification,
            assessments_dir=assessments_dir,
        )
        final_report_path(run_id, root).write_text(final, encoding="utf-8")


__all__ = [
    "LifecycleError",
    "analyse_evidence",
    "apply_action",
    "apply_remediation",
    "approve_action",
    "propose_action",
    "reconcile_actions_from_verification",
    "refresh_reports",
    "rollback_action",
    "_ui_from_lifecycle",
]
