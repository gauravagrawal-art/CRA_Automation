"""MockComplianceProvider — project Flow 2–4 artifacts into AssessmentView.

Uses the mock asset inventory and explicit applicability rules. Does not invent
evidence IDs or observations that the evidence run did not collect. Optional
lifecycle overlay supplies current vs initial status after mock remediation or
human evidence review.
"""

from __future__ import annotations

from typing import Any

from src.assessment.models import Assessment
from src.compliance.applicability import applicable_assets, mock_assets, primary_asset
from src.compliance.content import (
    display_severity,
    evidence_facts,
    index_evidence,
    short_finding,
    short_reason,
    short_remediation,
    short_requirement,
    short_verification,
)
from src.compliance.models import (
    AssessmentSummaryView,
    AssessmentView,
    Asset,
    ControlView,
    DisplaySeverity,
    FindingView,
    OverallStatus,
    RemediationView,
    ReviewHistoryEntry,
    UIStatus,
)
from src.compliance.status import map_verdict, overall_status
from src.evidence.models import EvidenceRun
from src.config import DEMO_PROVIDER, DEMO_TARGET_ID
from src.lifecycle.models import (
    ControlLifecycle,
    LifecycleDocument,
    LifecycleStatus,
    RemediationExecStatus,
)
from src.remediation.models import ActionType, RemediationDocument, RemediationItem, RemediationStatus
from src.services import runs_service
from src.services.registry_service import RegistryServiceError, load_approved


def _control_dict(registry: dict[str, Any] | None, control_id: str) -> dict[str, Any]:
    if not registry:
        return {"control_id": control_id}
    for control in registry.get("controls") or []:
        if control.get("control_id") == control_id:
            return control
    return {"control_id": control_id}


def _short_title(title: str) -> str:
    if ":" in title:
        return title.split(":", 1)[1].strip() or title
    return title


def _registry_as_dict() -> dict[str, Any] | None:
    try:
        approved = load_approved()
    except (RegistryServiceError, ValueError, FileNotFoundError, OSError):
        return None
    return approved.model_dump(mode="json")


def _lifecycle_to_ui(status: LifecycleStatus | None) -> UIStatus | None:
    if status is None:
        return None
    return UIStatus(status.value)


class MockComplianceProvider:
    """Build AssessmentView from on-disk assessment artifacts + mock assets."""

    def load(self, run_id: str) -> AssessmentView:
        assessment = runs_service.load_assessment(run_id)
        evidence = runs_service.load_evidence(run_id)
        remediation = runs_service.load_remediation(run_id)
        lifecycle = runs_service.load_lifecycle(run_id)
        assets = mock_assets()
        registry = _registry_as_dict()

        if assessment is None:
            return AssessmentView(
                run_id=run_id,
                assets=assets,
                summary=AssessmentSummaryView(
                    overall_status=OverallStatus.NOT_ASSESSED,
                    assets_assessed=len(assets),
                ),
                is_mock=True,
            )

        return self._build(
            assessment=assessment,
            evidence=evidence,
            remediation=remediation,
            lifecycle=lifecycle,
            assets=assets,
            registry=registry,
        )

    def from_artifacts(
        self,
        *,
        assessment: Assessment,
        evidence: EvidenceRun | None = None,
        remediation: RemediationDocument | None = None,
        lifecycle: LifecycleDocument | None = None,
        registry: dict[str, Any] | None = None,
    ) -> AssessmentView:
        """Build a view from in-memory artifacts (report generation / tests)."""
        return self._build(
            assessment=assessment,
            evidence=evidence,
            remediation=remediation,
            lifecycle=lifecycle,
            assets=mock_assets(),
            registry=registry if registry is not None else _registry_as_dict(),
        )

    def _build(
        self,
        *,
        assessment: Assessment,
        evidence: EvidenceRun | None,
        remediation: RemediationDocument | None,
        lifecycle: LifecycleDocument | None,
        assets: list[Asset],
        registry: dict[str, Any] | None,
    ) -> AssessmentView:
        evidence_by_id = index_evidence(evidence)
        rem_by_control = {
            item.finding_control_id: item for item in (remediation.items if remediation else [])
        }
        life_by_control: dict[str, ControlLifecycle] = (
            dict(lifecycle.controls) if lifecycle else {}
        )

        controls: list[ControlView] = []
        findings: list[FindingView] = []
        remediations: list[RemediationView] = []

        for result in assessment.results:
            control_meta = _control_dict(registry, result.control_id)
            if not control_meta.get("title"):
                control_meta = {
                    **control_meta,
                    "title": result.title,
                    "technical_control": result.technical_control,
                    "nms_interpretation": result.nms_interpretation,
                    "legal_requirement": result.legal_requirement,
                    "assertion_refs": [],
                    "evidence_plan": [],
                }

            engine_status = map_verdict(result.verdict)
            life = life_by_control.get(result.control_id)
            status = (
                _lifecycle_to_ui(life.current_status) if life is not None else engine_status
            )
            assert status is not None
            initial_status = (
                _lifecycle_to_ui(life.initial_status) if life is not None else engine_status
            )
            previous_status = (
                _lifecycle_to_ui(life.previous_status)
                if life is not None and life.previous_status is not None
                else None
            )

            applicable = applicable_assets(control_meta, assets)
            asset_ids = [a.asset_id for a in applicable]
            primary = primary_asset(
                control_meta,
                assets,
                status_is_fail=status is UIStatus.FAIL
                or engine_status is UIStatus.FAIL,
            )
            if status is UIStatus.NOT_APPLICABLE:
                asset_ids = []
                primary = None

            facts = evidence_facts(result, evidence_by_id)
            finding_text = short_finding(result, engine_status, facts)
            rem_text = short_remediation(result, engine_status)
            ver_text = short_verification(result, engine_status)
            severity = display_severity(result, status if status is UIStatus.FAIL else engine_status)
            reason = short_reason(result, engine_status, finding_text)

            rem_item = rem_by_control.get(result.control_id)
            if rem_item and rem_item.recommendation:
                rem_text = rem_item.recommendation.strip()
                if rem_text and rem_text[-1] not in ".!?":
                    rem_text += "."
            elif rem_item and rem_item.reason and not rem_text:
                rem_text = rem_item.reason.strip()

            rem_applied = False
            rem_status = ""
            proposed_change = ""
            affected_component = ""
            service_restart_required = False
            risk_and_impact = ""
            rollback_method = ""
            rem_approver = ""
            rem_approved_at = ""
            finding_status = (
                rem_item.status.value
                if rem_item is not None
                else RemediationStatus.OPEN.value
            )
            analysis_decision = ""
            analysis_reason = ""
            review_history: list[ReviewHistoryEntry] = []
            can_apply = False
            can_propose = False
            can_approve = False
            can_rollback = False
            apply_blocked_reason = ""
            can_submit = False
            target_executable = (
                assessment.metadata.target_id == DEMO_TARGET_ID
                and assessment.metadata.provider == DEMO_PROVIDER
            )

            if life is not None:
                if life.initial_finding:
                    finding_text = life.initial_finding
                active = None
                for rem in reversed(life.remediations):
                    active = rem
                    break
                if active:
                    rem_text = active.recommended_action or rem_text
                    rem_status = active.status.value
                    proposed_change = active.proposed_change or ""
                    affected_component = active.affected_component or ""
                    service_restart_required = bool(active.service_restart_required)
                    risk_and_impact = active.risk_and_impact or ""
                    rollback_method = active.rollback_method or ""
                    rem_approver = active.approver or ""
                    rem_approved_at = active.approved_at or ""
                    rem_applied = active.status in (
                        RemediationExecStatus.APPLIED,
                        RemediationExecStatus.APPLIED_UNVERIFIED,
                        RemediationExecStatus.APPLYING,
                        RemediationExecStatus.VERIFYING,
                        RemediationExecStatus.VERIFIED,
                    )
                    if active.verification_result:
                        ver_text = active.verification_result
                    can_approve = active.status is RemediationExecStatus.AWAITING_APPROVAL
                    can_apply = (
                        active.status is RemediationExecStatus.APPROVED and target_executable
                    )
                    can_rollback = active.status in (
                        RemediationExecStatus.APPLIED_UNVERIFIED,
                        RemediationExecStatus.FAILED,
                    )
                    if active.status is RemediationExecStatus.APPROVED and not target_executable:
                        apply_blocked_reason = (
                            "Apply is allow-listed only for the nextboss-demo mock target."
                        )
                        can_apply = False
                    if active.status is RemediationExecStatus.BLOCKED:
                        apply_blocked_reason = active.failure_reason or "Action is blocked."
                if life.last_analysis:
                    analysis_decision = (
                        life.last_analysis.resolve_final().value
                    )
                    analysis_reason = life.last_analysis.reason
                for attempt in life.review_attempts:
                    review_history.append(
                        ReviewHistoryEntry(
                            attempt=attempt.attempt,
                            evidence=attempt.submission.description
                            or ", ".join(
                                a.filename for a in attempt.submission.attachments
                            ),
                            decision=attempt.analysis.resolve_final().value,
                            reason=attempt.analysis.reason,
                            timestamp=attempt.timestamp,
                        )
                    )
                # Schema 1.0 legacy: overlay PASS after in-process verify.
                # Schema 1.1: REMEDIATION_PENDING until Flow 4 verify closes.
                can_submit = (
                    initial_status is UIStatus.REVIEW
                    and status
                    in (UIStatus.REVIEW, UIStatus.FAIL, UIStatus.REMEDIATION_PENDING)
                )
            else:
                can_submit = status is UIStatus.REVIEW

            eligible_technical = (
                rem_item is not None
                and rem_item.action_type is ActionType.TECHNICAL_REMEDIATION
                and rem_item.status is RemediationStatus.OPEN
                and engine_status is UIStatus.FAIL
                and bool(rem_text)
            )
            active_status = rem_status
            can_propose = eligible_technical and active_status in (
                "",
                RemediationExecStatus.PROPOSED.value,
                RemediationExecStatus.ROLLED_BACK.value,
                RemediationExecStatus.PENDING.value,
            )
            if not rem_status and eligible_technical and life is None:
                can_propose = True
            if life is not None and rem_status in (
                RemediationExecStatus.AWAITING_APPROVAL.value,
                RemediationExecStatus.APPROVED.value,
                RemediationExecStatus.APPLYING.value,
                RemediationExecStatus.APPLIED_UNVERIFIED.value,
                RemediationExecStatus.VERIFIED.value,
            ):
                can_propose = False

            # Legacy 1.0 path: allow apply button only when already APPROVED or
            # when no action workflow yet and FAIL with rem_text (tests/UI may
            # still hit the old single-click path via propose+approve elsewhere).
            if not can_apply and not rem_status and status is UIStatus.FAIL and bool(rem_text):
                # Prefer propose; do not enable apply until approved.
                can_apply = False

            view = ControlView(
                control_id=result.control_id,
                title=_short_title(result.title),
                requirement=short_requirement(result),
                asset_ids=asset_ids,
                status=status,
                initial_status=initial_status,
                previous_status=previous_status,
                severity=severity,
                evidence=facts,
                finding=finding_text,
                remediation=rem_text,
                verification=ver_text,
                reason=reason,
                engine_verdict=result.verdict.value,
                evidence_ids=list(result.evidence_ids),
                remediation_applied=rem_applied,
                remediation_status=rem_status,
                finding_status=finding_status,
                can_apply_remediation=can_apply,
                can_propose_remediation=can_propose,
                can_approve_remediation=can_approve,
                can_rollback_remediation=can_rollback,
                apply_blocked_reason=apply_blocked_reason,
                can_submit_evidence=can_submit,
                proposed_change=proposed_change,
                affected_component=affected_component,
                service_restart_required=service_restart_required,
                risk_and_impact=risk_and_impact,
                rollback_method=rollback_method,
                rem_approver=rem_approver,
                rem_approved_at=rem_approved_at,
                analysis_decision=analysis_decision,
                analysis_reason=analysis_reason,
                review_history=review_history,
                audit={
                    "expected_state": result.expected_state,
                    "observed_state": result.observed_state,
                    "evaluator_trace": [
                        e.model_dump(mode="json") for e in result.evaluator_trace
                    ],
                    "evidence_gaps": [
                        g.model_dump(mode="json") for g in result.evidence_gaps
                    ],
                    "evaluation_mode": result.evaluation_mode,
                    "narrative_source": result.narrative_source,
                },
            )
            controls.append(view)

            if status in (
                UIStatus.FAIL,
                UIStatus.REVIEW,
                UIStatus.REMEDIATION_PENDING,
            ) and primary is not None:
                findings.append(
                    FindingView(
                        control_id=result.control_id,
                        control_title=view.title,
                        asset_id=primary.asset_id,
                        asset_name=primary.name,
                        status=status,
                        severity=severity,
                        finding=finding_text or reason,
                        evidence_ids=list(result.evidence_ids),
                    )
                )

            if rem_item is not None and primary is not None:
                remediations.append(
                    self._remediation_view(
                        rem_item,
                        view,
                        primary,
                        rem_text,
                        ver_text,
                        overlay=life.remediations[-1] if life and life.remediations else None,
                    )
                )
            elif life is not None and life.remediations and primary is not None:
                active = life.remediations[-1]
                remediations.append(
                    RemediationView(
                        remediation_id=active.remediation_id,
                        control_id=result.control_id,
                        control_title=view.title,
                        asset_id=primary.asset_id,
                        asset_name=primary.name,
                        severity=severity,
                        issue=active.issue or finding_text,
                        recommended_action=active.recommended_action,
                        verification=active.verification_result
                        or active.verification_method
                        or ver_text,
                        status=active.status.value,
                        finding_status=finding_status,
                        action_status=active.status.value,
                        action_type=active.origin.value,
                        evidence_ids=list(result.evidence_ids),
                        proposed_change=active.proposed_change,
                        before_state=active.before_state,
                        expected_after_state=active.expected_after_state,
                        risk_and_impact=active.risk_and_impact,
                        rollback_method=active.rollback_method,
                        service_restart_required=active.service_restart_required,
                        affected_component=active.affected_component,
                        failure_reason=active.failure_reason,
                        can_propose=view.can_propose_remediation,
                        can_approve=view.can_approve_remediation,
                        can_apply=view.can_apply_remediation,
                        can_rollback=view.can_rollback_remediation,
                        apply_blocked_reason=view.apply_blocked_reason,
                        approver=active.approver,
                        approved_at=active.approved_at,
                    )
                )

        if remediation:
            known = {r.remediation_id for r in remediations}
            for item in remediation.items:
                if item.remediation_id in known:
                    continue
                control_view = next(
                    (c for c in controls if c.control_id == item.finding_control_id),
                    None,
                )
                control_meta = _control_dict(registry, item.finding_control_id)
                primary = primary_asset(control_meta, assets) or (
                    assets[0] if assets else None
                )
                if primary is None:
                    continue
                if control_view is None:
                    control_view = ControlView(
                        control_id=item.finding_control_id,
                        title=_short_title(item.finding_title),
                        status=map_verdict(item.finding_verdict),
                        finding=item.observed_state or item.reason,
                        remediation=item.recommendation or "",
                    )
                remediations.append(
                    self._remediation_view(
                        item,
                        control_view,
                        primary,
                        item.recommendation or control_view.remediation,
                        control_view.verification,
                    )
                )

        summary = self._summarize(controls, findings, assets)
        top = sorted(
            [f for f in findings if f.status is UIStatus.FAIL],
            key=lambda f: (
                0 if f.severity is DisplaySeverity.CRITICAL else
                1 if f.severity is DisplaySeverity.HIGH else
                2 if f.severity is DisplaySeverity.MEDIUM else 3,
                f.control_id,
            ),
        )[:5]

        meta = assessment.metadata
        return AssessmentView(
            run_id=meta.run_id,
            assessment_id=meta.assessment_id,
            target_id=meta.target_id,
            application_id=meta.application_id,
            provider=meta.provider,
            registry_version=meta.registry_version,
            registry_hash=meta.registry_hash,
            evidence_sha256=meta.evidence_sha256,
            generated_at=meta.generated_at,
            is_mock=meta.provider == "mock",
            summary=summary,
            assets=assets,
            controls=controls,
            findings=findings,
            remediations=remediations,
            top_findings=top,
        )

    def _remediation_view(
        self,
        item: RemediationItem,
        control: ControlView,
        asset: Asset,
        recommended: str,
        verification: str,
        overlay=None,
    ) -> RemediationView:
        ver = verification
        if item.verification and item.verification.evidence_keys and not ver:
            keys = ", ".join(item.verification.evidence_keys[:3])
            ver = f"Rescan and confirm: {keys}."
        finding_status = (
            item.status.value if hasattr(item.status, "value") else str(item.status)
        )
        action_status = ""
        if overlay is not None:
            action_status = overlay.status.value
        status = action_status or finding_status
        return RemediationView(
            remediation_id=item.remediation_id,
            control_id=item.finding_control_id,
            control_title=control.title or _short_title(item.finding_title),
            asset_id=asset.asset_id,
            asset_name=asset.name,
            severity=control.severity,
            issue=control.finding or item.observed_state or item.reason,
            recommended_action=recommended or item.recommendation or item.reason,
            verification=ver,
            status=status,
            finding_status=finding_status,
            action_status=action_status,
            action_type=(
                item.action_type.value
                if hasattr(item.action_type, "value")
                else str(item.action_type)
            ),
            evidence_ids=list(item.evidence_ids),
            proposed_change=(overlay.proposed_change if overlay else ""),
            before_state=(overlay.before_state if overlay else ""),
            expected_after_state=(overlay.expected_after_state if overlay else ""),
            risk_and_impact=(overlay.risk_and_impact if overlay else ""),
            rollback_method=(overlay.rollback_method if overlay else ""),
            service_restart_required=bool(
                overlay.service_restart_required if overlay else False
            ),
            affected_component=(overlay.affected_component if overlay else ""),
            failure_reason=(overlay.failure_reason if overlay else ""),
            can_propose=control.can_propose_remediation,
            can_approve=control.can_approve_remediation,
            can_apply=control.can_apply_remediation,
            can_rollback=control.can_rollback_remediation,
            apply_blocked_reason=control.apply_blocked_reason,
            approver=(overlay.approver if overlay else ""),
            approved_at=(overlay.approved_at if overlay else ""),
        )

    def _summarize(
        self,
        controls: list[ControlView],
        findings: list[FindingView],
        assets: list[Asset],
    ) -> AssessmentSummaryView:
        passed = sum(1 for c in controls if c.status is UIStatus.PASS)
        failed = sum(1 for c in controls if c.status is UIStatus.FAIL)
        review = sum(1 for c in controls if c.status is UIStatus.REVIEW)
        pending = sum(1 for c in controls if c.status is UIStatus.REMEDIATION_PENDING)
        na = sum(1 for c in controls if c.status is UIStatus.NOT_APPLICABLE)
        critical_high = sum(
            1
            for f in findings
            if f.severity in (DisplaySeverity.CRITICAL, DisplaySeverity.HIGH)
        )

        initially_passed = sum(
            1
            for c in controls
            if c.status is UIStatus.PASS
            and (c.initial_status or c.status) is UIStatus.PASS
            and not c.remediation_applied
            and not c.review_history
        )
        # Schema 1.1: only after action VERIFIED / finding VERIFIED_CLOSED.
        # Schema 1.0: overlay wrote APPLIED/VERIFYING/VERIFIED then UI PASS.
        passed_after_remediation = sum(
            1
            for c in controls
            if c.status is UIStatus.PASS
            and (c.initial_status or c.status) is UIStatus.FAIL
            and (
                c.finding_status == RemediationStatus.VERIFIED_CLOSED.value
                or c.remediation_status
                in (
                    RemediationExecStatus.VERIFIED.value,
                    RemediationExecStatus.APPLIED.value,
                    RemediationExecStatus.VERIFYING.value,
                )
            )
        )
        passed_after_review = sum(
            1
            for c in controls
            if c.status is UIStatus.PASS
            and (c.initial_status or c.status) is UIStatus.REVIEW
        )

        status = overall_status(
            failed=failed,
            review=review,
            assessed=bool(controls),
            remediation_pending=pending,
        )

        bullets: list[str] = []
        if failed:
            bullets.append(f"{failed} control(s) failed and need remediation.")
        if pending:
            bullets.append(f"{pending} control(s) have remediation in progress.")
        if review:
            bullets.append(f"{review} control(s) need human review or additional evidence.")
        if critical_high:
            bullets.append(
                f"{critical_high} critical/high finding(s) require priority attention."
            )
        if passed and not failed and not review and not pending:
            bullets.append("All applicable controls passed for this assessment run.")
        if not bullets and controls:
            bullets.append("Assessment completed; review controls for details.")

        return AssessmentSummaryView(
            overall_status=status,
            assets_assessed=len(assets),
            controls_assessed=len(controls),
            passed=passed,
            failed=failed,
            review=review,
            remediation_pending=pending,
            not_applicable=na,
            critical_high_findings=critical_high,
            initially_passed=initially_passed,
            passed_after_remediation=passed_after_remediation,
            passed_after_review=passed_after_review,
            remaining_failed=failed,
            pending_human_review=review,
            bullets=bullets[:5],
        )
