"""CLI for Flow 1 (ingest, validate, review, approve), Flow 2 (collect-evidence),
Flow 3 (assess) and Flow 4 (remediate, verify)."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.table import Table

from src.assessment.models import SUMMARY_FIELD_BY_VERDICT
from src.assessment.report import VERDICT_ORDER
from src.config import ASSESSMENTS_DIR, EVIDENCE_DIR, REGISTRY_DIR, TARGETS_DIR
from src.registry.approval import refuse_draft_as_approved
from src.services.registry_service import (
    RegistryServiceError,
    approve,
    build_draft,
    draft_path,
    resolve_registry_path,
    review_summary,
    validate_all,
)

if TYPE_CHECKING:
    from src.remediation.models import VerificationDocument

app = typer.Typer(name="nextboss-cra", help="NetBoss-XT CRA CLI")
console = Console()


def _fail(exc: RegistryServiceError) -> typer.Exit:
    """Report a refused precondition and stop with a non-zero exit code."""
    console.print(f"[red]{exc}[/red]")
    return typer.Exit(1)


@app.command("ingest")
def ingest_cmd() -> None:
    """Ingest documents and build document_registry.json + controls.draft.json."""
    console.print("[bold]Running Agent 1 — Document & Control Intelligence[/bold]")
    result = build_draft()
    console.print(
        f"  Documents: {result.documents} | "
        f"Requirements: {result.requirements} | "
        f"Controls: {result.controls}"
    )
    console.print(f"  Written: {REGISTRY_DIR / 'document_registry.json'}")
    console.print(f"  Written: {REGISTRY_DIR / 'controls.draft.json'}")


@app.command("validate-registry")
def validate_registry_cmd() -> None:
    """Validate draft registries against schemas and citation rules."""
    try:
        report = validate_all()
    except RegistryServiceError as exc:
        raise _fail(exc) from exc

    if report.errors:
        console.print(f"[red]Validation FAILED — {len(report.errors)} error(s)[/red]")
        for e in report.errors:
            console.print(f"  [red]ERROR[/red] {e}")
    else:
        console.print("[green]Validation PASSED[/green]")

    for w in report.warnings:
        console.print(f"  [yellow]WARN[/yellow] {w}")

    if report.errors:
        raise typer.Exit(1)


@app.command("review-registry")
def review_registry_cmd() -> None:
    """Human review summary for draft registries."""
    try:
        summary = review_summary()
    except RegistryServiceError as exc:
        raise _fail(exc) from exc

    table = Table(title="Source Documents")
    table.add_column("ID")
    table.add_column("Authority")
    table.add_column("Binding")
    table.add_column("Present")
    for d in summary.documents:
        table.add_row(d.document_id, str(d.authority_level), d.binding_status, str(d.present))
    console.print(table)

    console.print(f"\nRequirements: {summary.requirements}")
    console.print(f"Controls: {summary.controls}")
    console.print(f"Conflicts: {len(summary.conflicts)}")
    console.print(f"Human review items: {summary.human_review_items}")
    console.print(f"Unresolved: {summary.unresolved_items}")
    console.print(f"Controls flagged for human review: {summary.controls_flagged}")

    if summary.conflicts:
        console.print("\n[bold yellow]Conflicts requiring review:[/bold yellow]")
        for c in summary.conflicts:
            console.print(f"  {c.conflict_id}: {c.description}")

    coverage = Table(title="Security Area Coverage")
    coverage.add_column("Area")
    coverage.add_column("Name")
    coverage.add_column("CRA points")
    coverage.add_column("Controls")
    coverage.add_column("Evidence items")
    coverage.add_column("Assertion refs")

    for row in summary.coverage:
        coverage.add_row(
            row.area_id,
            row.name,
            row.cra_points,
            str(row.controls),
            str(row.evidence_items),
            str(row.assertion_refs),
        )
    console.print(coverage)


@app.command("approve-registry")
def approve_registry_cmd(
    approver: str = typer.Option(..., help="Name of the approver"),
    version: str = typer.Option("1.0.0", help="Semantic version for approved baseline"),
    allow_conflicts: bool = typer.Option(False, help="Allow approval despite blocking conflicts"),
) -> None:
    """Approve draft controls and create immutable versioned baseline."""
    try:
        result = approve(approver=approver, version=version, allow_conflicts=allow_conflicts)
    except RegistryServiceError as exc:
        raise _fail(exc) from exc

    console.print(f"[green]Approved registry written:[/green] {result.path}")
    console.print(f"  Hash: {result.manifest.approved_registry_hash}")

    # Verify draft cannot be used as approved
    try:
        refuse_draft_as_approved(draft_path())
        console.print("[red]ERROR: draft loader did not reject DRAFT status[/red]")
        raise typer.Exit(1)
    except ValueError:
        console.print("[green]Verified: DRAFT registry correctly refused as approved input[/green]")


@app.command("collect-evidence")
def collect_evidence_cmd(
    target: Path = typer.Option(
        TARGETS_DIR / "nextboss-demo.mock.json",
        help="Runtime target profile describing where this scan runs",
    ),
    registry: Path | None = typer.Option(
        None, help="Approved registry path (defaults to the latest approved version)"
    ),
    provider: str | None = typer.Option(
        None, help="Override the provider declared in the target profile"
    ),
    scenario: str | None = typer.Option(
        None, help="Override the mock scenario: compliant | partial | vulnerable"
    ),
    application: str | None = typer.Option(
        None,
        help="Application in the target environment: router_monitor | switch_monitor | sbc_monitor",
    ),
    run_id: str | None = typer.Option(None, help="Fixed run ID, for reproducible runs"),
    output_dir: Path = typer.Option(EVIDENCE_DIR, help="Directory to write runs into"),
) -> None:
    """Collect technical evidence for an approved control registry.

    This flow makes no compliance decision and emits no verdict.
    """
    from src.display import known_application, resolve_application_id
    from src.evidence.runner import RegistryIntegrityError, collect_evidence

    try:
        registry_path = resolve_registry_path(registry)
    except RegistryServiceError as exc:
        raise _fail(exc) from exc

    if application and not known_application(application):
        console.print(f"[red]Unknown application '{application}'.[/red]")
        raise typer.Exit(1)

    try:
        run_dir, run = collect_evidence(
            registry_path=registry_path,
            target_path=target,
            output_dir=output_dir,
            run_id=run_id,
            provider_override=provider,
            scenario_override=scenario,
            application_id=resolve_application_id(application),
        )
    except (RegistryIntegrityError, FileNotFoundError, ValueError, NotImplementedError) as exc:
        console.print(f"[red]Evidence collection refused: {exc}[/red]")
        raise typer.Exit(1) from exc

    from src.display import application_label, target_env_label

    summary = run.summary
    app_name = application_label(run.run.application_id)
    scope = target_env_label(run.run.target_id)
    if app_name:
        scope = f"{scope} · {app_name}"
    console.print(
        f"[bold]Evidence run[/bold] {run.run.run_id} "
        f"(target env {scope}, provider {run.run.provider})"
    )
    console.print(f"  Registry: {run.run.registry_version} @ {run.run.registry_hash[:16]}...")

    table = Table(title="Collection summary")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Controls in registry", str(summary.controls_in_registry))
    table.add_row("Evidence requests", str(summary.evidence_requests_total))
    table.add_row("  technical", str(summary.evidence_requests_technical))
    table.add_row("  documentary / human", str(summary.evidence_requests_documentary))
    table.add_row("  collectable", str(summary.evidence_requests_collectable))
    table.add_row("MCP calls executed", str(summary.mcp_calls_planned))
    table.add_row("Calls saved by dedup", str(summary.mcp_calls_deduplicated))
    table.add_row("Evidence items", str(summary.evidence_items))
    table.add_row("Collection errors", str(summary.collection_errors))
    console.print(table)

    if summary.by_status:
        status_table = Table(title="By collection status")
        status_table.add_column("Status")
        status_table.add_column("Count", justify="right")
        for status, count in summary.by_status.items():
            status_table.add_row(status, str(count))
        console.print(status_table)

    if summary.by_reason_code:
        reason_table = Table(title="By reason code (not compliance verdicts)")
        reason_table.add_column("Reason code")
        reason_table.add_column("Count", justify="right")
        for reason, count in summary.by_reason_code.items():
            reason_table.add_row(reason, str(count))
        console.print(reason_table)

    console.print(f"[green]Written:[/green] {run_dir / 'evidence.json'}")
    console.print(f"[green]Raw artifacts:[/green] {run_dir / 'raw'}")


@app.command("assess")
def assess_cmd(
    run_id: str = typer.Option(..., help="Evidence run to assess, e.g. RUN-DEMO-0001"),
    registry: Path | None = typer.Option(
        None, help="Approved registry path (defaults to the latest approved version)"
    ),
    evidence_dir: Path = typer.Option(EVIDENCE_DIR, help="Directory holding evidence runs"),
    output_dir: Path = typer.Option(ASSESSMENTS_DIR, help="Directory to write assessments into"),
    target_id: str | None = typer.Option(
        None, help="Assert the evidence was collected against this target ID"
    ),
    llm: bool = typer.Option(
        False, "--llm/--no-llm", help="Enable Agent 2 narration (explanations only)"
    ),
) -> None:
    """Assess collected evidence and render the technical readiness report.

    Verdicts come from the deterministic rule engine. Agent 2, when enabled,
    only rewrites explanations and can never change a verdict.
    """
    from src.assessment.runner import PreflightError, assess
    from src.llm.agent2 import NullAgent2Provider

    try:
        registry_path = resolve_registry_path(registry)
    except RegistryServiceError as exc:
        raise _fail(exc) from exc

    provider = NullAgent2Provider() if llm else None
    if llm:
        console.print(
            "[yellow]LLM narration requested; no model provider is configured in this "
            "POC, so deterministic template explanations are used.[/yellow]"
        )

    try:
        out_dir, assessment = assess(
            run_id=run_id,
            registry_path=registry_path,
            evidence_dir=evidence_dir,
            output_dir=output_dir,
            provider=provider,
            expected_target_id=target_id,
        )
    except (PreflightError, FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Assessment refused: {exc}[/red]")
        raise typer.Exit(1) from exc

    meta = assessment.metadata
    console.print(
        f"[bold]Assessment[/bold] {meta.assessment_id} "
        f"(run {meta.run_id}, target {meta.target_id}, provider {meta.provider})"
    )
    console.print(f"  Registry: {meta.registry_version} @ {meta.registry_hash[:16]}...")
    console.print(f"  LLM narration: {meta.llm_narration}")

    summary = assessment.summary
    table = Table(title="Verdict summary (technical readiness, not certification)")
    table.add_column("Verdict")
    table.add_column("Count", justify="right")
    table.add_row("Total controls", str(summary.total))
    for verdict in VERDICT_ORDER:
        table.add_row(verdict.value, str(getattr(summary, SUMMARY_FIELD_BY_VERDICT[verdict])))
    console.print(table)

    for limitation in assessment.limitations:
        console.print(f"[yellow]Limitation[/yellow] {limitation.code.value}: {limitation.detail}")

    console.print(f"[green]Written:[/green] {out_dir / 'assessment.json'}")
    console.print(f"[green]Report:[/green] {out_dir / 'assessment.html'}")


@app.command("remediate")
def remediate_cmd(
    run_id: str = typer.Option(..., help="Assessed run to remediate, e.g. RUN-DEMO-0001"),
    registry: Path | None = typer.Option(
        None, help="Approved registry path (defaults to the latest approved version)"
    ),
    evidence_dir: Path = typer.Option(EVIDENCE_DIR, help="Directory holding evidence runs"),
    assessments_dir: Path = typer.Option(
        ASSESSMENTS_DIR, help="Directory holding assessments and Flow 4 output"
    ),
    previous_run: str | None = typer.Option(
        None, help="Earlier assessed run whose findings this run should verify"
    ),
) -> None:
    """Compose advisory remediation and render the final report.

    Recommendations are copied from the approved registry's remediation seed.
    Nothing is executed and no target is changed: verification means re-running
    Flow 2 and Flow 3 and comparing the assessments.
    """
    from src.remediation.models import ActionType, RemediationStatus
    from src.remediation.runner import RemediationPreflightError, remediate

    try:
        registry_path = resolve_registry_path(registry)
    except RegistryServiceError as exc:
        raise _fail(exc) from exc

    try:
        out_dir, remediation = remediate(
            run_id=run_id,
            registry_path=registry_path,
            evidence_dir=evidence_dir,
            assessments_dir=assessments_dir,
            previous_run_id=previous_run,
        )
    except (RemediationPreflightError, FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Remediation refused: {exc}[/red]")
        raise typer.Exit(1) from exc

    meta = remediation.metadata
    console.print(
        f"[bold]Remediation[/bold] {meta.remediation_run_id} "
        f"(assessment {meta.assessment_id}, run {meta.run_id}, target {meta.target_id})"
    )
    console.print(f"  Registry: {meta.registry_version} @ {meta.registry_hash[:16]}...")
    if meta.provider == "mock":
        console.print("[yellow]  Provider is 'mock': findings describe synthetic data.[/yellow]")

    summary = remediation.summary
    table = Table(title="Advisory remediation (no change is applied to any target)")
    table.add_column("Action")
    table.add_column("Count", justify="right")
    table.add_row("Controls assessed", str(summary.controls_assessed))
    table.add_row("Items", str(summary.items_total))
    for action in ActionType:
        table.add_row(action.value, str(summary.by_action_type.get(action.value, 0)))
    for status in RemediationStatus:
        table.add_row(status.value, str(summary.by_status.get(status.value, 0)))
    console.print(table)

    if remediation.verification is not None:
        _print_verification(remediation.verification)

    console.print(f"[green]Written:[/green] {out_dir / 'remediation.json'}")
    console.print(f"[green]Report:[/green] {out_dir / 'final-report.html'}")


@app.command("verify")
def verify_cmd(
    previous_run: str = typer.Option(..., help="Earlier assessed run holding the findings"),
    new_run: str = typer.Option(..., help="Later assessed run collected after the change"),
    assessments_dir: Path = typer.Option(
        ASSESSMENTS_DIR, help="Directory holding assessments and Flow 4 output"
    ),
) -> None:
    """Check whether a later assessment closes an earlier run's findings.

    Only a new evidence-backed PASS under the same approved baseline closes a
    finding. A recommendation, or a statement that a fix was applied, does not.
    """
    from src.remediation.runner import verify_runs

    try:
        out_dir, verification = verify_runs(
            previous_run_id=previous_run,
            new_run_id=new_run,
            assessments_dir=assessments_dir,
        )
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Verification refused: {exc}[/red]")
        raise typer.Exit(1) from exc

    from src.lifecycle.service import reconcile_actions_from_verification

    reconcile_actions_from_verification(
        previous_run, new_run, assessments_dir=assessments_dir
    )

    _print_verification(verification)
    console.print(f"[green]Written:[/green] {out_dir / 'verification.json'}")


@app.command("propose-remediation")
def propose_remediation_cmd(
    run_id: str = typer.Option(..., "--run-id", help="Assessed run with remediation.json"),
    control_id: str = typer.Option(..., "--control-id"),
    actor: str = typer.Option("operator", "--actor"),
    assessments_dir: Path | None = typer.Option(None, "--assessments-dir"),
) -> None:
    """Propose an allow-listed remediation action from an eligible OPEN finding."""
    from src.lifecycle.service import LifecycleError, propose_action

    try:
        entry = propose_action(
            run_id, control_id, actor=actor, assessments_dir=assessments_dir
        )
    except LifecycleError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    rem = entry.remediations[-1]
    console.print(
        f"[green]Proposed[/green] {rem.remediation_id} → {rem.status.value} "
        f"(finding stays OPEN)"
    )


@app.command("approve-remediation")
def approve_remediation_cmd(
    run_id: str = typer.Option(..., "--run-id"),
    control_id: str = typer.Option(..., "--control-id"),
    approver: str = typer.Option(..., "--approver"),
    action: str = typer.Option("APPROVE", "--action", help="APPROVE or REJECT"),
    assessments_dir: Path | None = typer.Option(None, "--assessments-dir"),
) -> None:
    """Explicitly approve or reject a remediation proposal."""
    from src.lifecycle.service import LifecycleError, approve_action

    try:
        entry = approve_action(
            run_id,
            control_id,
            approver=approver,
            action=action,
            assessments_dir=assessments_dir,
        )
    except LifecycleError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    rem = entry.remediations[-1]
    console.print(f"[green]{rem.status.value}[/green] by {rem.approver}")


@app.command("apply-remediation")
def apply_remediation_cmd(
    run_id: str = typer.Option(..., "--run-id"),
    control_id: str = typer.Option(..., "--control-id"),
    actor: str = typer.Option("operator", "--actor"),
    assessments_dir: Path | None = typer.Option(None, "--assessments-dir"),
) -> None:
    """Apply an approved allow-listed demo action. Does not close the finding."""
    from src.lifecycle.service import LifecycleError, apply_action

    try:
        entry = apply_action(
            run_id, control_id, actor=actor, assessments_dir=assessments_dir
        )
    except LifecycleError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    rem = entry.remediations[-1]
    console.print(
        f"[green]{rem.status.value}[/green] {rem.execution_result} "
        "(finding stays OPEN until re-scan verifies PASS)"
    )


@app.command("rollback-remediation")
def rollback_remediation_cmd(
    run_id: str = typer.Option(..., "--run-id"),
    control_id: str = typer.Option(..., "--control-id"),
    actor: str = typer.Option("operator", "--actor"),
    assessments_dir: Path | None = typer.Option(None, "--assessments-dir"),
) -> None:
    """Roll back a demo overlay operation. Finding stays OPEN."""
    from src.lifecycle.service import LifecycleError, rollback_action

    try:
        entry = rollback_action(
            run_id, control_id, actor=actor, assessments_dir=assessments_dir
        )
    except LifecycleError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    rem = entry.remediations[-1]
    console.print(f"[green]{rem.status.value}[/green]")


@app.command("serve")
def serve_cmd(
    host: str = typer.Option("127.0.0.1", help="Interface to bind; loopback by default"),
    port: int = typer.Option(8000, help="Port to listen on"),
    reload: bool = typer.Option(False, help="Reload on source changes (development)"),
) -> None:
    """Serve the local web UI for the whole Flow 1-4 workflow.

    The UI calls the same service functions these commands do. It is a local
    single-user tool: it has no authentication, so binding it to anything other
    than loopback would expose every artifact on this machine.
    """
    # Imported here so the CLI keeps working without the optional [ui] extra.
    try:
        import uvicorn
    except ModuleNotFoundError as exc:
        console.print(
            "[red]The web UI needs the optional 'ui' extra.[/red]\n"
            '  pip install -e ".[ui]"'
        )
        raise typer.Exit(1) from exc

    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            f"[yellow]Warning: binding to {host} exposes this UI beyond localhost. "
            "It has no authentication.[/yellow]"
        )

    console.print(f"[bold]NetBoss-XT CRA UI[/bold] → http://{host}:{port}")
    uvicorn.run("src.web.app:app", host=host, port=port, reload=reload, log_level="info")


def _print_verification(verification: "VerificationDocument") -> None:
    """Render the closure decision for both Flow 4 commands."""
    meta = verification.metadata
    console.print(
        f"[bold]Verification[/bold] {meta.previous_run_id} -> {meta.new_run_id} "
        f"(target {meta.new_target_id})"
    )
    if not verification.baseline_comparable:
        code = verification.blocked_reason_code
        console.print(
            f"[yellow]VERIFICATION_BLOCKED[/yellow] {code.value if code else ''}: "
            "the assessments are not the same baseline, so nothing can be closed."
        )

    summary = verification.summary
    table = Table(title="Closure status (evidence-backed only)")
    table.add_column("Outcome")
    table.add_column("Count", justify="right")
    table.add_row("Findings compared", str(summary.findings_compared))
    table.add_row("VERIFIED_CLOSED", str(summary.verified_closed))
    table.add_row("STILL_OPEN", str(summary.still_open))
    table.add_row("VERIFICATION_BLOCKED", str(summary.blocked))
    console.print(table)


if __name__ == "__main__":
    app()
