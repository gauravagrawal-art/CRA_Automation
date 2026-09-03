"""Orchestrate mock remediation apply/verify and human evidence analysis.

Domain rules enforced here:
- Suggested remediation != PASS
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
from src.config import ASSESSMENTS_DIR, HUMAN_EVIDENCE_MAX_BYTES
from src.evidence.models import EvidenceRun
from src.lifecycle.analyzer import get_evidence_analyzer
from src.lifecycle.executor import get_remediation_executor
from src.lifecycle.models import (
    AnalysisDecision,
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
    make_evidence_id,
    make_remediation_id,
)
from src.lifecycle.store import human_evidence_dir, load_lifecycle, save_lifecycle
from src.remediation.models import RemediationDocument
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


def _load_evidence_run(run_id: str, assessments_dir: Path | None) -> EvidenceRun | None:
    if assessments_dir is not None:
        candidate = assessments_dir.parent / "evidence" / run_id / "evidence.json"
        if candidate.exists():
            return EvidenceRun.model_validate(
                json.loads(candidate.read_text(encoding="utf-8"))
            )
        return None
    return runs_service.load_evidence(run_id)


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
        ):
            return rem
    return entry.remediations[-1] if entry.remediations else None


def _seed_recommendation(
    assessment: Assessment,
    control_id: str,
    remediation_doc: RemediationDocument | None,
) -> tuple[str, str]:
    """Return (recommended_action, issue) from Flow 4 advisory item or registry seed."""
    result = _control_result(assessment, control_id)
    if remediation_doc:
        for item in remediation_doc.items:
            if item.finding_control_id == control_id:
                action = (item.recommendation or item.reason or "").strip()
                issue = (item.observed_state or item.reason or "").strip()
                if action:
                    return action, issue
    seed = result.remediation_seed or {}
    action = str(seed.get("recommendation") or "").strip()
    issue = result.observed_state or result.reason or ""
    return action, issue


def apply_remediation(
    run_id: str,
    control_id: str,
    *,
    assessments_dir: Path | None = None,
    clock: Clock | None = None,
) -> ControlLifecycle:
    """Apply mock remediation then verify. PASS only after successful verification."""
    now = (clock or _utc_now)()
    root = assessments_dir or ASSESSMENTS_DIR
    assessment = _load_assessment(run_id, assessments_dir)
    if assessment is None:
        raise LifecycleError(f"No assessment for run {run_id}.")

    remediation_doc = _load_remediation_doc(run_id, assessments_dir)
    result = _control_result(assessment, control_id)

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
        LifecycleStatus.FAIL,
        LifecycleStatus.REMEDIATION_PENDING,
    ):
        raise LifecycleError(
            f"Control {control_id} cannot be remediated in status "
            f"{entry.current_status.value}."
        )

    rem = _active_remediation(entry)
    action, issue = _seed_recommendation(assessment, control_id, remediation_doc)
    if rem and rem.recommended_action:
        action = rem.recommended_action
        issue = rem.issue or issue or entry.initial_finding

    if not action:
        raise LifecycleError(f"No recommended remediation action for {control_id}.")

    # Scan FAIL/PARTIAL, or FAIL after human-review analysis.
    scan_fail = result.verdict in (Verdict.FAIL, Verdict.PARTIAL)
    human_fail = (
        entry.initial_status is LifecycleStatus.REVIEW and bool(entry.review_attempts)
    )
    if not scan_fail and not human_fail:
        raise LifecycleError(
            "Apply Remediation is only available for failed remediable controls."
        )

    origin = (
        RemediationOrigin.HUMAN_REVIEW
        if human_fail
        else RemediationOrigin.SCAN
    )
    if rem is None or rem.status in (
        RemediationExecStatus.VERIFIED,
        RemediationExecStatus.NOT_REQUIRED,
    ):
        rem = RemediationRecord(
            remediation_id=make_remediation_id(run_id, control_id, origin),
            control_id=control_id,
            asset_id=entry.asset_id,
            issue=issue or entry.initial_finding,
            recommended_action=action,
            verification_method="Mock verification scan",
            status=RemediationExecStatus.PENDING,
            created_at=now,
            origin=origin,
        )
        entry.remediations.append(rem)
    else:
        rem.recommended_action = action
        rem.issue = issue or rem.issue or entry.initial_finding

    executor = get_remediation_executor()

    # Trail: IN_PROGRESS → APPLIED → VERIFYING → VERIFIED. Never PASS in apply().
    rem.status = RemediationExecStatus.IN_PROGRESS
    entry.previous_status = entry.current_status
    entry.current_status = LifecycleStatus.REMEDIATION_PENDING
    entry.updated_at = now

    apply_result = executor.apply(rem, clock=now)
    if not apply_result.get("ok"):
        rem.status = RemediationExecStatus.FAILED
        rem.execution_result = str(apply_result.get("execution_result") or "Apply failed.")
        entry.current_status = LifecycleStatus.FAIL
        doc.updated_at = now
        save_lifecycle(doc, root)
        raise LifecycleError(rem.execution_result)

    rem.status = RemediationExecStatus.APPLIED
    rem.execution_result = str(apply_result.get("execution_result") or "")
    rem.applied_at = str(apply_result.get("applied_at") or now)

    rem.status = RemediationExecStatus.VERIFYING
    verify_result = executor.verify(
        rem,
        control_id=control_id,
        finding=rem.issue or entry.initial_finding,
        recommended_action=rem.recommended_action,
        clock=now,
    )
    if not verify_result.get("ok"):
        rem.status = RemediationExecStatus.FAILED
        rem.verification_result = str(
            verify_result.get("verification_result") or "Verification failed."
        )
        entry.current_status = LifecycleStatus.FAIL
        doc.updated_at = now
        save_lifecycle(doc, root)
        raise LifecycleError(rem.verification_result)

    rem.status = RemediationExecStatus.VERIFIED
    rem.verification_result = str(verify_result.get("verification_result") or "")
    rem.verified_at = str(verify_result.get("verified_at") or now)

    entry.previous_status = LifecycleStatus.FAIL
    entry.current_status = LifecycleStatus.PASS
    entry.updated_at = now

    _, _, asset_type = _asset_for_control(control_id, result, _registry_dict())
    entry.dataset_records.append(
        DatasetRecord(
            control_id=control_id,
            control_requirement=short_requirement(result),
            asset_type=asset_type,
            evidence="; ".join(entry.initial_evidence),
            human_decision="",
            ai_decision="",
            final_decision=LifecycleStatus.PASS.value,
            decision_reason="Passed after mock remediation and verification.",
            remediation=rem.recommended_action,
            verification_result=rem.verification_result,
            recorded_at=now,
        )
    )

    doc.updated_at = now
    save_lifecycle(doc, root)
    return entry


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

    # Allow re-submit after FAIL / still REVIEW / REMEDIATION_PENDING after weak evidence.
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


# Re-export for callers that need UIStatus mapping helpers.
__all__ = [
    "LifecycleError",
    "analyse_evidence",
    "apply_remediation",
    "refresh_reports",
    "_ui_from_lifecycle",
]
