"""Workflow actions the UI can trigger, each backed by an existing flow runner.

Nothing here re-implements a flow. Every action resolves its inputs, calls the
same function the CLI calls, and reports progress. No action writes to a target:
verification means running Flow 2 and Flow 3 again and comparing assessments.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from src.assessment.runner import assess
from src.display import application_label, resolve_application_id
from src.evidence.runner import collect_evidence
from src.remediation.runner import remediate, verify_runs
from src.services import runs_service
from src.services.context import TargetOption, find_target
from src.services.jobs import Job, JobHandle, registry as jobs
from src.services.registry_service import (
    RegistryServiceError,
    ValidationReport,
    approve,
    build_draft,
    draft_path,
    resolve_registry_path,
    validate_all,
)


class WorkflowError(RuntimeError):
    """An action was refused before anything ran. The message is user-facing."""


# --- validation state -------------------------------------------------------
#
# Approval is gated on a successful validation of the *current* draft. The
# result is keyed on the draft's mtime, so editing or rebuilding the draft
# invalidates it rather than leaving a stale pass in place.

_validation_lock = threading.Lock()
_validation: dict[str, object] = {}


@dataclass
class ValidationState:
    report: ValidationReport | None = None
    checked_at: str = ""
    stale: bool = False

    @property
    def ran(self) -> bool:
        return self.report is not None

    @property
    def approved_allowed(self) -> bool:
        return self.report is not None and self.report.ok and not self.stale

    @property
    def gate_reason(self) -> str:
        if self.report is None:
            return "Validate the registry before approving it."
        if self.stale:
            return "The draft changed after the last validation. Validate it again."
        if not self.report.ok:
            return f"Validation found {len(self.report.errors)} error(s). Approval is blocked."
        return ""


def _draft_mtime() -> int:
    try:
        return draft_path().stat().st_mtime_ns
    except OSError:
        return 0


def record_validation(report: ValidationReport) -> None:
    with _validation_lock:
        _validation["report"] = report
        _validation["mtime"] = _draft_mtime()
        _validation["at"] = datetime.now(timezone.utc).isoformat()


def validation_state() -> ValidationState:
    with _validation_lock:
        report = _validation.get("report")
        if report is None:
            return ValidationState()
        return ValidationState(
            report=report,  # type: ignore[arg-type]
            checked_at=str(_validation.get("at", "")),
            stale=_validation.get("mtime") != _draft_mtime(),
        )


def clear_validation() -> None:
    with _validation_lock:
        _validation.clear()


# --- registry actions -------------------------------------------------------


def start_build_registry() -> Job:
    def work(handle: JobHandle) -> None:
        handle.step("Reading source documents")
        result = build_draft()
        clear_validation()
        handle.step(
            f"Parsed {result.documents} document(s), extracted {result.requirements} requirement(s)"
        )
        handle.step(f"Wrote draft registry with {result.controls} control(s)")

    return jobs.start(
        job_type="REGISTRY_BUILD",
        title="Building draft control registry",
        redirect="/registry",
        work=work,
    )


def start_validate_registry() -> Job:
    def work(handle: JobHandle) -> None:
        handle.step("Loading product profile and security assertions")
        handle.step("Re-parsing source PDFs to check citations")
        report = validate_all()
        record_validation(report)
        if report.errors:
            handle.step(f"Validation FAILED with {len(report.errors)} error(s)")
        else:
            handle.step(f"Validation PASSED with {len(report.warnings)} warning(s)")

    return jobs.start(
        job_type="REGISTRY_VALIDATE",
        title="Validating draft registry",
        redirect="/registry",
        work=work,
    )


def approve_registry_now(
    *, approver: str, version: str, allow_conflicts: bool = False
) -> str:
    """Approve synchronously: it is fast, and the user is waiting on a confirmation.

    Refuses unless the current draft has just validated cleanly, so the UI can
    never approve something the CLI would have rejected. ``allow_conflicts``
    mirrors the CLI ``--allow-conflicts`` override for unresolved blocking
    document conflicts.
    """
    approver = approver.strip()
    version = version.strip()
    if not approver:
        raise WorkflowError("An approver name is required.")
    if not version:
        raise WorkflowError("A version number is required.")

    state = validation_state()
    if not state.approved_allowed:
        raise WorkflowError(state.gate_reason)

    try:
        result = approve(
            approver=approver, version=version, allow_conflicts=allow_conflicts
        )
    except RegistryServiceError as exc:
        raise WorkflowError(str(exc)) from exc
    return result.manifest.approved_registry_hash


# --- scan / assess / remediate ----------------------------------------------


def _resolve_target(target_key: str) -> TargetOption:
    option = find_target(target_key)
    if option is None:
        raise WorkflowError("Unknown target profile.")
    if not option.supported:
        raise WorkflowError(option.detail or "This target provider is not supported.")
    return option


def _resolve_scenario(option: TargetOption, scenario: str | None) -> str | None:
    if not scenario or scenario == option.environment:
        return None
    from src.evidence.targets import MOCK_SCENARIOS

    if scenario not in MOCK_SCENARIOS:
        raise WorkflowError(f"Unknown mock scenario '{scenario}'.")
    return scenario


def _resolve_application(application: str | None) -> str:
    from src.display import known_application, normalize_application_id

    if not application:
        return resolve_application_id(None)
    if not known_application(application):
        raise WorkflowError(f"Unknown application '{application}'.")
    return normalize_application_id(application)


@dataclass
class ScanRequest:
    """A validated scan request. Built server-side; never trusted from the form."""

    target: TargetOption
    registry_path: Path
    scenario: str | None = None
    application_id: str = ""
    then_assess: bool = False
    then_remediate: bool = False
    previous_run: str | None = None


def plan_scan(
    *,
    target_key: str,
    scenario: str | None = None,
    application: str | None = None,
    chain: str = "evidence",
    previous_run: str | None = None,
) -> ScanRequest:
    """Validate a scan request and resolve everything it needs, before starting."""
    option = _resolve_target(target_key)
    application_id = _resolve_application(application)
    try:
        registry_path = resolve_registry_path()
    except RegistryServiceError as exc:
        raise WorkflowError(str(exc)) from exc

    if previous_run is not None and previous_run not in runs_service.list_run_ids():
        raise WorkflowError(f"Unknown previous run '{previous_run}'.")

    return ScanRequest(
        target=option,
        registry_path=registry_path,
        scenario=_resolve_scenario(option, scenario),
        application_id=application_id,
        then_assess=chain in ("full", "verify"),
        then_remediate=chain in ("full", "verify"),
        previous_run=previous_run,
    )


def start_scan(request: ScanRequest) -> Job:
    """Run Flow 2, and optionally Flow 3 and Flow 4, as one background job."""

    def work(handle: JobHandle) -> None:
        handle.step(f"Registry validated: {request.registry_path.name}")
        handle.step(f"Target resolved: {request.target.target_id} ({request.target.provider})")
        if request.application_id:
            handle.step(
                f"Application: {application_label(request.application_id) or request.application_id}"
            )
        if request.scenario:
            handle.step(f"Mock scenario pinned: {request.scenario}")

        handle.step("Planning evidence requests from the approved registry")
        run_dir, run = collect_evidence(
            registry_path=request.registry_path,
            target_path=request.target.path,
            scenario_override=request.scenario,
            application_id=request.application_id,
        )
        run_id = run.run.run_id
        handle.set_run_id(run_id)
        handle.set_redirect(f"/evidence?run={run_id}")
        summary = run.summary
        handle.step(
            f"{summary.evidence_requests_total} evidence request(s) planned, "
            f"{summary.mcp_calls_deduplicated} call(s) saved by deduplication"
        )
        handle.step(
            f"{summary.mcp_calls_planned} MCP call(s) executed into run {run_id}"
        )
        collected = summary.by_status.get("COLLECTED", 0)
        handle.step(f"{collected} of {summary.evidence_items} evidence item(s) collected")

        if not request.then_assess:
            handle.step("Evidence ready. Assessment has not run yet.")
            return

        handle.step("Evaluating approved rules against collected evidence")
        assess(run_id=run_id, registry_path=request.registry_path)
        handle.set_redirect(f"/assessment?run={run_id}")
        overview = runs_service.run_overview(run_id)
        handle.step(
            "Assessment complete: "
            + ", ".join(
                f"{count} {verdict}"
                for verdict, count in overview.verdict_counts.items()
                if count
            )
        )

        if not request.then_remediate:
            return

        handle.step("Composing advisory remediation from approved seeds")
        remediate(
            run_id=run_id,
            registry_path=request.registry_path,
            previous_run_id=request.previous_run,
        )
        handle.set_redirect(f"/remediation?run={run_id}")
        if request.previous_run:
            from src.lifecycle.service import reconcile_actions_from_verification

            reconcile_actions_from_verification(request.previous_run, run_id)
            verification = runs_service.load_verification(run_id)
            if verification is None:
                remediation = runs_service.load_remediation(run_id)
                verification = remediation.verification if remediation else None
            if verification is not None:
                handle.step(
                    f"Verification against {request.previous_run}: "
                    f"{verification.summary.verified_closed} closed, "
                    f"{verification.summary.still_open} still open"
                )
        handle.step("Remediation and final report ready")

    titles = {
        (False, False): "Collecting evidence",
        (True, False): "Collecting evidence and assessing",
        (True, True): "Running full assessment",
    }
    title = titles.get((request.then_assess, request.then_remediate), "Collecting evidence")
    if request.previous_run:
        title = f"Re-scanning and verifying against {request.previous_run}"

    return jobs.start(
        job_type="EVIDENCE_COLLECTION",
        title=title,
        redirect="/evidence",
        work=work,
    )


def start_assessment(run_id: str) -> Job:
    """Assess an evidence run that has already been collected."""
    if runs_service.load_evidence(run_id) is None:
        raise WorkflowError(f"Run '{run_id}' has no collected evidence.")
    try:
        registry_path = resolve_registry_path()
    except RegistryServiceError as exc:
        raise WorkflowError(str(exc)) from exc

    def work(handle: JobHandle) -> None:
        handle.step(f"Checking run {run_id} against the approved registry")
        handle.step("Evaluating approved rules against collected evidence")
        assess(run_id=run_id, registry_path=registry_path)
        overview = runs_service.run_overview(run_id)
        handle.step(
            "Assessment complete: "
            + ", ".join(
                f"{count} {verdict}"
                for verdict, count in overview.verdict_counts.items()
                if count
            )
        )

    return jobs.start(
        job_type="ASSESSMENT",
        title=f"Assessing {run_id}",
        redirect=f"/assessment?run={run_id}",
        work=work,
    )


def start_remediation(run_id: str, previous_run: str | None = None) -> Job:
    """Compose remediation for an assessed run, optionally verifying an earlier one."""
    if runs_service.load_assessment(run_id) is None:
        raise WorkflowError(f"Run '{run_id}' has not been assessed.")
    if previous_run is not None:
        if previous_run == run_id:
            raise WorkflowError("A run cannot verify itself.")
        if runs_service.load_assessment(previous_run) is None:
            raise WorkflowError(f"Run '{previous_run}' has not been assessed.")
    try:
        registry_path = resolve_registry_path()
    except RegistryServiceError as exc:
        raise WorkflowError(str(exc)) from exc

    def work(handle: JobHandle) -> None:
        handle.step(f"Reading assessment for {run_id}")
        handle.step("Copying recommendations from approved remediation seeds")
        remediate(
            run_id=run_id,
            registry_path=registry_path,
            previous_run_id=previous_run,
        )
        if previous_run:
            from src.lifecycle.service import reconcile_actions_from_verification

            reconcile_actions_from_verification(previous_run, run_id)
        overview = runs_service.run_overview(run_id)
        handle.step(
            f"{overview.open_findings} open, {overview.verified_closed} verified closed"
        )
        handle.step("Final report written")

    return jobs.start(
        job_type="REMEDIATION",
        title=f"Composing remediation for {run_id}",
        redirect=f"/remediation?run={run_id}",
        work=work,
    )


def start_verification(previous_run: str, new_run: str) -> Job:
    """Compare two assessments and record which findings closed."""
    if previous_run == new_run:
        raise WorkflowError("A run cannot verify itself.")
    for run_id in (previous_run, new_run):
        if runs_service.load_assessment(run_id) is None:
            raise WorkflowError(f"Run '{run_id}' has not been assessed.")

    def work(handle: JobHandle) -> None:
        handle.step(f"Comparing {previous_run} with {new_run}")
        _, verification = verify_runs(previous_run_id=previous_run, new_run_id=new_run)
        from src.lifecycle.service import reconcile_actions_from_verification

        reconcile_actions_from_verification(previous_run, new_run)
        if not verification.baseline_comparable:
            code = verification.blocked_reason_code
            handle.step(
                f"VERIFICATION_BLOCKED ({code.value if code else 'unknown'}): "
                "the runs are not the same baseline, so nothing can close."
            )
            return
        handle.step(
            f"{verification.summary.verified_closed} closed, "
            f"{verification.summary.still_open} still open"
        )

    return jobs.start(
        job_type="VERIFICATION",
        title=f"Verifying {new_run} against {previous_run}",
        redirect=f"/remediation?run={new_run}",
        work=work,
    )
