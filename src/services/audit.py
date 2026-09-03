"""Approval audit log for the UI.

Collects named-approver events already stored on the approved registry
manifest and on remediation-action records. Nothing here invents actors
or timestamps.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.lifecycle.store import load_lifecycle
from src.services import runs_service
from src.services.registry_service import registry_state


@dataclass(frozen=True)
class AuditEvent:
    kind: str
    action: str
    actor: str
    at: str
    subject: str
    detail: str = ""
    run_id: str = ""
    control_id: str = ""


@dataclass
class AuditLog:
    registry: AuditEvent | None = None
    assessments: list[AuditEvent] = field(default_factory=list)
    remediations: list[AuditEvent] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return (
            self.registry is None
            and not self.assessments
            and not self.remediations
        )


def collect_audit_log() -> AuditLog:
    """Assessment-baseline and remediation approval records for the Audit tab."""
    log = AuditLog()
    registry = registry_state()

    if registry.approver and registry.approved_at:
        log.registry = AuditEvent(
            kind="ASSESSMENT",
            action="APPROVE",
            actor=registry.approver,
            at=registry.approved_at,
            subject=f"Control registry v{registry.latest_version}",
            detail=(
                "This approved baseline is what every assessment evaluates against. "
                f"Content hash {registry.latest_hash or '—'}."
            ),
        )

    for run in runs_service.list_runs():
        assessment = runs_service.load_assessment(run.run_id)
        if assessment is not None:
            meta = assessment.metadata
            log.assessments.append(
                AuditEvent(
                    kind="ASSESSMENT",
                    action="ASSESS",
                    actor=registry.approver or "—",
                    at=meta.generated_at,
                    subject=meta.run_id,
                    detail=(
                        f"Target {meta.target_id} · registry {meta.registry_version} "
                        f"· provider {meta.provider}"
                    ),
                    run_id=meta.run_id,
                )
            )

        lifecycle = load_lifecycle(run.run_id)
        if lifecycle is None:
            continue
        for control in lifecycle.controls.values():
            for rem in control.remediations:
                if not rem.approver or not rem.approved_at:
                    continue
                action = (
                    rem.approval_action.value
                    if rem.approval_action is not None
                    else "APPROVE"
                )
                log.remediations.append(
                    AuditEvent(
                        kind="REMEDIATION",
                        action=action,
                        actor=rem.approver,
                        at=rem.approved_at,
                        subject=rem.control_id,
                        detail=(
                            f"{rem.remediation_id} · {rem.status.value}. "
                            + (rem.proposed_change or rem.recommended_action or "")
                        ).strip(),
                        run_id=run.run_id,
                        control_id=rem.control_id,
                    )
                )

    log.assessments.sort(key=lambda e: (e.at or "", e.subject), reverse=True)
    log.remediations.sort(key=lambda e: (e.at or "", e.subject), reverse=True)
    return log
