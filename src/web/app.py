"""FastAPI routes for the CRA assessment UI.

Routes read artifacts and call the shared service layer. No route contains
compliance logic: nothing here decides a verdict, recomputes a count or invents
a recommendation. Actions are POST-only, same-origin, and every one of them
delegates to the same function the CLI calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.assessment.models import Verdict
from src.compliance.models import UIStatus
from src.compliance.provider import get_compliance_provider
from src.config import (
    DEFAULT_APPLICATION_ID,
    MCP_CAPABILITY_CATALOG,
    MCP_PATH_ALLOWLIST,
    POLICY_DIR,
    PRODUCT_DIR,
    PROJECT_ROOT,
)
from src.display import (
    application_label,
    scope_caption,
    scope_short,
    target_env_label,
)
from src.evidence.models import CollectionStatus
from src.lifecycle.service import (
    LifecycleError,
    analyse_evidence,
    apply_action,
    approve_action,
    propose_action,
    refresh_reports,
    rollback_action,
)
from src.registry.models import ApplicabilityStatus, EvidenceMode
from src.remediation.models import ActionType, RemediationStatus
from src.services import context, runs_service, workflow
from src.services.jobs import registry as jobs
from src.services.registry_service import (
    RegistryServiceError,
    blocking_conflicts,
    load_approved,
    load_document_registry,
    load_draft,
    point_key_from_title,
    product_context,
    suggest_next_version,
)
from src.services.runs_service import ArtifactError
from src.services.workflow import WorkflowError
from src.web import charts
from src.web.glossary import GLOSSARY, explain

BASE_DIR = Path(__file__).resolve().parent
PAGE_SIZE = 50

app = FastAPI(
    title="NetBoss-XT CRA Technical Readiness",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def _fmt_ts(value: str | None) -> str:
    """Render an ISO timestamp as a readable local-style string."""
    if not value:
        return "—"
    text = str(value).replace("T", " ")
    if "." in text:
        text = text.split(".", 1)[0]
    return text.replace("+00:00", " UTC").strip()


def _short(value: str | None, length: int = 12) -> str:
    if not value:
        return "—"
    text = str(value)
    return text if len(text) <= length else f"{text[:length]}…"


def _pretty(value: Any) -> str:
    """Enum-style token to sentence case, e.g. HUMAN_REVIEW -> Human review."""
    if value is None:
        return "—"
    text = str(getattr(value, "value", value))
    return text.replace("_", " ").capitalize()


def _tojson(value: Any, indent: int | None = None) -> str:
    """JSON for <pre> blocks. Jinja still HTML-escapes the result."""
    return json.dumps(value, indent=indent, default=str, ensure_ascii=False)


def _unique(values: Any) -> list[Any]:
    """Preserve-order unique, for table cells that would otherwise repeat."""
    seen: set[Any] = set()
    out: list[Any] = []
    for item in values:
        if item in seen or item in (None, ""):
            continue
        seen.add(item)
        out.append(item)
    return out


def _page_num(params: dict[str, Any], default: int = 1) -> int:
    try:
        return max(1, int(params.get("page", default) or default))
    except (TypeError, ValueError):
        return default


def _query(params: dict[str, Any], **overrides: Any) -> str:
    """Build a query string from current filters plus overrides; drop empties."""
    merged = {**params, **overrides}
    clean = {k: v for k, v in merged.items() if v not in (None, "", "all")}
    return f"?{urlencode(clean)}" if clean else ""


templates.env.filters["ts"] = _fmt_ts
templates.env.filters["short"] = _short
templates.env.filters["pretty"] = _pretty
templates.env.filters["tojson"] = _tojson
templates.env.filters["unique"] = _unique
templates.env.filters["target_env"] = target_env_label
templates.env.filters["application_name"] = application_label
templates.env.globals["explain"] = explain
templates.env.globals["query"] = _query
templates.env.globals["scope_caption"] = scope_caption
templates.env.globals["scope_short"] = scope_short
templates.env.globals["DEFAULT_APPLICATION_ID"] = DEFAULT_APPLICATION_ID
templates.env.globals["Verdict"] = Verdict
templates.env.globals["VERDICT_ORDER"] = charts.VERDICT_ORDER
templates.env.globals["UIStatus"] = UIStatus
templates.env.globals["CollectionStatus"] = CollectionStatus
templates.env.globals["ActionType"] = ActionType
templates.env.globals["RemediationStatus"] = RemediationStatus
templates.env.globals["ApplicabilityStatus"] = ApplicabilityStatus
templates.env.globals["EvidenceMode"] = EvidenceMode
templates.env.globals["GLOSSARY"] = GLOSSARY


@app.exception_handler(ArtifactError)
@app.exception_handler(WorkflowError)
@app.exception_handler(RegistryServiceError)
def _known_failure(request: Request, exc: Exception) -> Response:
    """Turn a refused or unreadable artifact into a page, not a stack trace."""
    return _page(
        request,
        "error.html",
        nav="assessment",
        title="Cannot continue",
        message=str(exc),
    )


# --- shared page scaffolding ------------------------------------------------


def _page(
    request: Request,
    template: str,
    *,
    nav: str,
    title: str,
    stage: str | None = None,
    **extra: Any,
) -> Response:
    """Render a page with the shell context every template expects."""
    ctx = context.workspace()
    if stage:
        ctx.stage = stage
    payload: dict[str, Any] = {
        "request": request,
        "ctx": ctx,
        "nav": nav,
        "page_title": title,
        "notice": request.query_params.get("msg", ""),
        "notice_level": request.query_params.get("level", "info"),
        "running_jobs": jobs.running(),
    }
    payload.update(extra)
    return templates.TemplateResponse(request, template, payload)


def _redirect(href: str, message: str = "", level: str = "info") -> RedirectResponse:
    """Post/redirect/get, carrying an optional message for the next page."""
    if message:
        joiner = "&" if "?" in href else "?"
        href = f"{href}{joiner}{urlencode({'msg': message, 'level': level})}"
    return RedirectResponse(href, status_code=303)


def _guard_origin(request: Request) -> None:
    """Reject cross-origin form posts.

    The UI has no authentication because it is a local single-user tool, which
    means any page in the browser could otherwise post to it. Comparing the
    Origin against this server's host closes that without adding sessions.
    """
    origin = request.headers.get("origin") or request.headers.get("referer")
    if not origin:
        return
    host = urlparse(origin).netloc
    if host and host != request.headers.get("host"):
        raise WorkflowError("Cross-origin request refused.")


def _resolve_run(requested: str | None, *, require_assessment: bool = False) -> str | None:
    """Pick the run a page should show: the requested one, else the newest."""
    known = runs_service.list_run_ids()
    if requested and requested in known:
        return requested
    runs = runs_service.list_runs()
    if require_assessment:
        for run in runs:
            if run.has_assessment:
                return run.run_id
        return None
    latest = runs_service.latest_run(runs)
    return latest.run_id if latest else None


def _paginate(items: list, page: int) -> tuple[list, dict[str, Any]]:
    total = len(items)
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(max(page, 1), pages)
    start = (page - 1) * PAGE_SIZE
    window = items[start : start + PAGE_SIZE]
    meta = {
        "page": page,
        "pages": pages,
        "total": total,
        "start": start + 1 if total else 0,
        "end": start + len(window),
        "show": pages > 1,
    }
    return window, meta


# --- Assessment home --------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def assessment_home(request: Request) -> Response:
    params = dict(request.query_params)
    run_id = _resolve_run(params.get("run"), require_assessment=True)
    view = get_compliance_provider().load(run_id) if run_id else None
    unassessed = [r for r in runs_service.list_runs() if r.has_evidence and not r.has_assessment]
    return _page(
        request,
        "assessment_home.html",
        nav="assessment",
        title="Assessment",
        stage="assessment",
        view=view,
        unassessed=unassessed,
    )


# --- Controls ---------------------------------------------------------------


@app.get("/controls", response_class=HTMLResponse)
def controls_page(request: Request) -> Response:
    params = dict(request.query_params)
    run_id = _resolve_run(params.get("run"), require_assessment=True)
    view = get_compliance_provider().load(run_id) if run_id else None
    status = params.get("status", "")
    q = params.get("q", "").strip().lower()
    page = _page_num(params)

    controls = list(view.controls) if view else []
    filtered = []
    for control in controls:
        if status and control.status.value != status:
            continue
        if q and q not in f"{control.control_id} {control.title}".lower():
            continue
        filtered.append(control)

    window, pager = _paginate(filtered, page)
    return _page(
        request,
        "controls.html",
        nav="controls",
        title="Controls",
        stage="controls",
        view=view,
        controls=window,
        pager=pager,
        filters=params,
    )


# --- Findings ---------------------------------------------------------------


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request) -> Response:
    params = dict(request.query_params)
    run_id = _resolve_run(params.get("run"), require_assessment=True)
    view = get_compliance_provider().load(run_id) if run_id else None
    status = params.get("status", "")
    page = _page_num(params)

    findings = list(view.findings) if view else []
    if status:
        findings = [f for f in findings if f.status.value == status]

    window, pager = _paginate(findings, page)
    return _page(
        request,
        "findings.html",
        nav="findings",
        title="Findings",
        stage="findings",
        view=view,
        findings=window,
        pager=pager,
        filters=params,
    )


# --- Sources & Registry -----------------------------------------------------


@app.get("/registry", response_class=HTMLResponse)
def registry_page(request: Request) -> Response:
    params = dict(request.query_params)
    q = params.get("q", "").strip().lower()
    applicability = params.get("applicability", "")
    evidence_mode = params.get("mode", "")
    review = params.get("review", "")
    cra = params.get("cra", "")
    page = _page_num(params)

    state = context.workspace().registry
    documents: list = []
    controls: list = []
    load_error = ""

    try:
        documents = list(load_document_registry().documents)
    except (RegistryServiceError, ValueError) as exc:
        load_error = str(exc)

    try:
        controls = list(load_approved().controls) if state.scannable else list(load_draft().controls)
    except (RegistryServiceError, ValueError) as exc:
        load_error = load_error or str(exc)

    cra_points = sorted(
        {p for p in (point_key_from_title(c.title) for c in controls) if p}
    )

    filtered = []
    for control in controls:
        if applicability and control.applicability.status.value != applicability:
            continue
        if review == "yes" and not control.human_review_required:
            continue
        if review == "no" and control.human_review_required:
            continue
        if evidence_mode:
            modes = {item.mode.value for item in control.evidence_plan}
            if evidence_mode not in modes:
                continue
        if cra and point_key_from_title(control.title) != cra:
            continue
        if q and q not in f"{control.control_id} {control.title}".lower():
            continue
        filtered.append(control)

    window, pager = _paginate(filtered, page)
    profile, profile_error = product_context()
    conflicts = blocking_conflicts() if state.draft_exists else []

    return _page(
        request,
        "registry.html",
        nav="registry",
        title="Sources & Registry",
        stage="registry" if not state.scannable else None,
        documents=documents,
        controls=window,
        matched=len(filtered),
        total_controls=len(controls),
        pager=pager,
        filters=params,
        cra_points=cra_points,
        profile=profile,
        profile_error=profile_error,
        load_error=load_error,
        validation=workflow.validation_state(),
        registry_source="approved" if state.scannable else "draft",
        next_version=suggest_next_version(),
        blocking_conflicts=conflicts,
    )


@app.get("/registry/control/{control_id}", response_class=HTMLResponse)
def registry_control(request: Request, control_id: str) -> Response:
    state = context.workspace().registry
    try:
        controls = load_approved().controls if state.scannable else load_draft().controls
    except (RegistryServiceError, ValueError) as exc:
        return _page(
            request, "error.html", nav="registry", title="Control", message=str(exc)
        )

    control = next((c for c in controls if c.control_id == control_id), None)
    if control is None:
        return _page(
            request,
            "error.html",
            nav="registry",
            title="Control not found",
            message=f"No control '{control_id}' in the current registry.",
        )

    return _page(
        request,
        "registry_control.html",
        nav="registry",
        title=control.control_id,
        control=control,
        cra_point=point_key_from_title(control.title),
        registry_source="approved" if state.scannable else "draft",
    )


# --- Evidence ---------------------------------------------------------------


@app.get("/evidence", response_class=HTMLResponse)
def evidence_page(request: Request) -> Response:
    params = dict(request.query_params)
    run_id = _resolve_run(params.get("run"))
    status = params.get("status", "")
    q = params.get("q", "").strip().lower()
    page = _page_num(params)

    run = runs_service.load_evidence(run_id) if run_id else None
    items = list(run.evidence) if run else []

    filtered = []
    for item in items:
        if status and item.status.value != status:
            continue
        if q:
            keys = " ".join(r.evidence_key for r in item.requested_by)
            if q not in f"{item.evidence_id} {item.tool} {keys}".lower():
                continue
        filtered.append(item)

    window, pager = _paginate(filtered, page)

    return _page(
        request,
        "evidence.html",
        nav="evidence",
        title="Evidence",
        stage="evidence",
        run=run,
        run_id=run_id,
        items=window,
        matched=len(filtered),
        pager=pager,
        filters=params,
        applications=context.applications(),
        selected_application=run.run.application_id if run else DEFAULT_APPLICATION_ID,
    )


@app.get("/evidence/{run_id}/{evidence_id}", response_class=HTMLResponse)
def evidence_detail(request: Request, run_id: str, evidence_id: str) -> Response:
    if run_id not in runs_service.list_run_ids():
        return _page(
            request, "error.html", nav="evidence", title="Run not found",
            message=f"No run '{run_id}'.",
        )
    run = runs_service.load_evidence(run_id)
    item = next((e for e in run.evidence if e.evidence_id == evidence_id), None) if run else None
    if item is None:
        return _page(
            request, "error.html", nav="evidence", title="Evidence not found",
            message=f"No evidence item '{evidence_id}' in run {run_id}.",
        )
    return _page(
        request,
        "evidence_item.html",
        nav="evidence",
        title=item.evidence_id,
        stage="evidence",
        run=run,
        run_id=run_id,
        item=item,
    )


# --- Assessment (alias → home) ----------------------------------------------


@app.get("/assessment", response_class=HTMLResponse)
def assessment_page(request: Request) -> Response:
    """Keep the old URL; the assessment home is now ``/``."""
    qs = request.url.query
    target = f"/?{qs}" if qs else "/"
    return RedirectResponse(target, status_code=303)


@app.get("/assessment/control/{control_id}", response_class=HTMLResponse)
def assessment_control(request: Request, control_id: str) -> Response:
    run_id = _resolve_run(request.query_params.get("run"), require_assessment=True)
    view = get_compliance_provider().load(run_id) if run_id else None
    control = (
        next((c for c in view.controls if c.control_id == control_id), None)
        if view
        else None
    )
    if control is None:
        return _page(
            request, "error.html", nav="controls", title="Control not found",
            message=f"No assessed control '{control_id}' in run {run_id}.",
        )

    assets_by_id = {a.asset_id: a for a in (view.assets if view else [])}
    assets = [assets_by_id[aid] for aid in control.asset_ids if aid in assets_by_id]
    remediation = runs_service.load_remediation(run_id) if run_id else None
    item = (
        next((i for i in remediation.items if i.finding_control_id == control_id), None)
        if remediation
        else None
    )

    return _page(
        request,
        "assessment_control.html",
        nav="controls",
        title=control.control_id,
        stage="controls",
        run_id=run_id,
        control=control,
        assets=assets,
        remediation_item=item,
        view=view,
    )


# --- Remediation & Verify ---------------------------------------------------


@app.get("/remediation", response_class=HTMLResponse)
def remediation_page(request: Request) -> Response:
    params = dict(request.query_params)
    run_id = _resolve_run(params.get("run"), require_assessment=True)
    view = get_compliance_provider().load(run_id) if run_id else None

    remediation = runs_service.load_remediation(run_id) if run_id else None
    verification = runs_service.load_verification(run_id) if run_id else None
    if verification is None and remediation is not None:
        verification = remediation.verification

    return _page(
        request,
        "remediation.html",
        nav="remediation",
        title="Remediation",
        stage="remediation",
        view=view,
        remediation=remediation,
        verification=verification,
        run_id=run_id,
        filters=params,
        previous_run=runs_service.previous_assessed_run(run_id) if run_id else None,
        assessed_runs=[r for r in runs_service.list_runs() if r.has_assessment],
        targets=context.list_targets(),
        applications=context.applications(),
        selected_application=(
            view.application_id if view and view.application_id else DEFAULT_APPLICATION_ID
        ),
    )


# --- Audit ------------------------------------------------------------------


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request) -> Response:
    from src.services.audit import collect_audit_log

    return _page(
        request,
        "audit.html",
        nav="audit",
        title="Audit",
        audit=collect_audit_log(),
    )


# --- Reports ----------------------------------------------------------------


@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request) -> Response:
    return _page(
        request,
        "reports.html",
        nav="reports",
        title="Reports",
        runs=runs_service.list_runs(),
    )


@app.get("/runs/{run_id}", response_class=HTMLResponse)
def run_report(request: Request, run_id: str) -> Response:
    if run_id not in runs_service.list_run_ids():
        return _page(
            request, "error.html", nav="reports", title="Run not found",
            message=f"No run '{run_id}'.",
        )

    view = get_compliance_provider().load(run_id)
    overview = runs_service.run_overview(run_id)

    return _page(
        request,
        "report_view.html",
        nav="reports",
        title=f"Report {run_id}",
        run_id=run_id,
        overview=overview,
        view=view,
        has_html_report=runs_service.report_path(run_id).exists(),
        has_final_report=runs_service.final_report_path(run_id).exists(),
    )


#: Artifact key -> resolver. Only these files may be served.
_ARTIFACTS = {
    "evidence.json": (runs_service.evidence_path, "application/json"),
    "assessment.json": (runs_service.assessment_path, "application/json"),
    "remediation.json": (runs_service.remediation_path, "application/json"),
    "verification.json": (runs_service.verification_path, "application/json"),
    "assessment.html": (runs_service.report_path, "text/html"),
    "final-report.html": (runs_service.final_report_path, "text/html"),
}


@app.get("/runs/{run_id}/artifact/{name}")
def run_artifact(run_id: str, name: str) -> Response:
    """Serve one known artifact of a known run.

    Both the run and the filename come from fixed sets, so no request can point
    this at a path the workflow did not produce.
    """
    if run_id not in runs_service.list_run_ids() or name not in _ARTIFACTS:
        return Response("Not found", status_code=404)
    resolver, media_type = _ARTIFACTS[name]
    path = resolver(run_id)
    if not path.exists():
        return Response("Not found", status_code=404)
    return FileResponse(path, media_type=media_type, filename=f"{run_id}-{name}")


# --- Settings ---------------------------------------------------------------


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request) -> Response:
    profile, profile_error = product_context()
    return _page(
        request,
        "settings.html",
        nav="settings",
        title="Settings",
        paths=[
            ("Project root", PROJECT_ROOT),
            ("Registry", PROJECT_ROOT / "registry"),
            ("Approved baselines", PROJECT_ROOT / "registry" / "approved"),
            ("Evidence runs", PROJECT_ROOT / "evidence"),
            ("Assessments", PROJECT_ROOT / "assessments"),
            ("Targets", PROJECT_ROOT / "targets"),
            ("Product profile", PRODUCT_DIR),
            ("Policy", POLICY_DIR),
        ],
        mcp_tools=MCP_CAPABILITY_CATALOG,
        path_allowlist=MCP_PATH_ALLOWLIST,
        glossary=sorted(GLOSSARY.items()),
        profile=profile,
        profile_error=profile_error,
    )


# --- Jobs -------------------------------------------------------------------


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_page(request: Request, job_id: str) -> Response:
    job = jobs.get(job_id)
    if job is None:
        return _page(
            request, "error.html", nav="overview", title="Job not found",
            message="That job is no longer held in memory. Its artifacts, if any, are on disk.",
        )
    return _page(request, "job.html", nav="job", title=job.title, job=job)


@app.get("/jobs/{job_id}/panel", response_class=HTMLResponse)
def job_panel(request: Request, job_id: str) -> Response:
    """The polling fragment: just the progress panel, no shell."""
    job = jobs.get(job_id)
    if job is None:
        return HTMLResponse('<p class="muted">Job not found.</p>', status_code=404)
    return templates.TemplateResponse(
        request, "partials/job_panel.html", {"request": request, "job": job}
    )


# --- Actions ----------------------------------------------------------------


def _action(request: Request, run: Any, fallback: str) -> RedirectResponse:
    """Run an action, turning a refusal into a message on the page it came from."""
    try:
        _guard_origin(request)
        return run()
    except (WorkflowError, RegistryServiceError) as exc:
        return _redirect(fallback, str(exc), "error")


@app.post("/actions/registry/build")
def action_build(request: Request) -> Response:
    def run() -> RedirectResponse:
        job = workflow.start_build_registry()
        return _redirect(f"/jobs/{job.job_id}")

    return _action(request, run, "/registry")


@app.post("/actions/registry/validate")
def action_validate(request: Request) -> Response:
    def run() -> RedirectResponse:
        job = workflow.start_validate_registry()
        return _redirect(f"/jobs/{job.job_id}")

    return _action(request, run, "/registry")


@app.post("/actions/registry/approve")
def action_approve(
    request: Request,
    approver: str = Form(...),
    version: str = Form(...),
    allow_conflicts: str = Form(""),
) -> Response:
    def run() -> RedirectResponse:
        digest = workflow.approve_registry_now(
            approver=approver,
            version=version,
            allow_conflicts=allow_conflicts.lower() in {"true", "on", "1", "yes"},
        )
        return _redirect(
            "/registry",
            f"Registry v{version.strip()} approved. Hash {digest[:16]}…",
            "success",
        )

    return _action(request, run, "/registry")


@app.post("/actions/evidence/collect")
def action_collect(
    request: Request,
    target: str = Form(...),
    application: str = Form(""),
    chain: str = Form("evidence"),
) -> Response:
    def run() -> RedirectResponse:
        plan = workflow.plan_scan(
            target_key=target,
            application=application or None,
            chain="full" if chain == "full" else "evidence",
        )
        job = workflow.start_scan(plan)
        return _redirect(f"/jobs/{job.job_id}")

    return _action(request, run, "/evidence")


@app.post("/actions/assessment/run")
def action_assess(request: Request, run_id: str = Form(...)) -> Response:
    def run() -> RedirectResponse:
        job = workflow.start_assessment(run_id)
        return _redirect(f"/jobs/{job.job_id}")

    return _action(request, run, "/assessment")


@app.post("/actions/remediation/compose")
def action_compose(
    request: Request,
    run_id: str = Form(...),
    previous_run: str = Form(""),
) -> Response:
    def run() -> RedirectResponse:
        job = workflow.start_remediation(run_id, previous_run or None)
        return _redirect(f"/jobs/{job.job_id}")

    return _action(request, run, "/remediation")


@app.post("/actions/verification/run")
def action_verify(
    request: Request,
    previous_run: str = Form(...),
    new_run: str = Form(...),
) -> Response:
    def run() -> RedirectResponse:
        job = workflow.start_verification(previous_run, new_run)
        return _redirect(f"/jobs/{job.job_id}")

    return _action(request, run, "/remediation")


@app.post("/actions/rescan-verify")
def action_rescan_verify(
    request: Request,
    target: str = Form(...),
    previous_run: str = Form(...),
    application: str = Form(""),
) -> Response:
    """Re-scan and verify: Flow 2, then Flow 3, then Flow 4 verification.

    Nothing is written to the target. Closure comes only from the new
    assessment's own evidence.
    """

    def run() -> RedirectResponse:
        plan = workflow.plan_scan(
            target_key=target,
            application=application or None,
            chain="verify",
            previous_run=previous_run,
        )
        job = workflow.start_scan(plan)
        return _redirect(f"/jobs/{job.job_id}")

    return _action(request, run, "/remediation")


@app.post("/actions/lifecycle/propose-remediation")
async def action_propose_remediation(
    request: Request,
    run_id: str = Form(...),
    control_id: str = Form(...),
    actor: str = Form("operator"),
) -> Response:
    """Create a remediation proposal and submit it for approval."""

    def run() -> RedirectResponse:
        propose_action(run_id.strip(), control_id.strip(), actor=(actor or "operator").strip())
        return _redirect(
            f"/assessment/control/{control_id.strip()}?run={run_id.strip()}",
            "Remediation proposal submitted for approval. Finding remains OPEN.",
            "success",
        )

    try:
        _guard_origin(request)
        return run()
    except LifecycleError as exc:
        return _redirect(
            f"/assessment/control/{control_id.strip()}?run={run_id.strip()}",
            str(exc),
            "error",
        )
    except (WorkflowError, RegistryServiceError) as exc:
        return _redirect("/remediation", str(exc), "error")


@app.post("/actions/lifecycle/approve-remediation")
async def action_approve_remediation(
    request: Request,
    run_id: str = Form(...),
    control_id: str = Form(...),
    approver: str = Form(...),
    approval_action: str = Form("APPROVE"),
) -> Response:
    """Explicitly approve or reject a remediation proposal."""

    def run() -> RedirectResponse:
        approve_action(
            run_id.strip(),
            control_id.strip(),
            approver=approver,
            action=approval_action,
        )
        label = "approved" if approval_action.upper() == "APPROVE" else "rejected"
        return _redirect(
            f"/assessment/control/{control_id.strip()}?run={run_id.strip()}",
            f"Remediation proposal {label}. Finding remains OPEN.",
            "success",
        )

    try:
        _guard_origin(request)
        return run()
    except LifecycleError as exc:
        return _redirect(
            f"/assessment/control/{control_id.strip()}?run={run_id.strip()}",
            str(exc),
            "error",
        )
    except (WorkflowError, RegistryServiceError) as exc:
        return _redirect("/remediation", str(exc), "error")


@app.post("/actions/lifecycle/apply-remediation")
async def action_apply_remediation(
    request: Request,
    run_id: str = Form(...),
    control_id: str = Form(...),
    actor: str = Form("operator"),
) -> Response:
    """Apply an approved allow-listed demo action. Does not close the finding."""

    def run() -> RedirectResponse:
        apply_action(
            run_id.strip(),
            control_id.strip(),
            actor=(actor or "operator").strip(),
        )
        try:
            refresh_reports(run_id.strip())
        except Exception:
            pass
        return _redirect(
            f"/assessment/control/{control_id.strip()}?run={run_id.strip()}",
            "Remediation applied on the demo target (APPLIED_UNVERIFIED). "
            "Finding remains OPEN — re-scan and verify to close it.",
            "success",
        )

    try:
        _guard_origin(request)
        return run()
    except LifecycleError as exc:
        return _redirect(
            f"/assessment/control/{control_id.strip()}?run={run_id.strip()}",
            str(exc),
            "error",
        )
    except (WorkflowError, RegistryServiceError) as exc:
        return _redirect("/remediation", str(exc), "error")


@app.post("/actions/lifecycle/rollback-remediation")
async def action_rollback_remediation(
    request: Request,
    run_id: str = Form(...),
    control_id: str = Form(...),
    actor: str = Form("operator"),
) -> Response:
    """Roll back a demo overlay operation. Finding stays OPEN."""

    def run() -> RedirectResponse:
        rollback_action(
            run_id.strip(),
            control_id.strip(),
            actor=(actor or "operator").strip(),
        )
        try:
            refresh_reports(run_id.strip())
        except Exception:
            pass
        return _redirect(
            f"/assessment/control/{control_id.strip()}?run={run_id.strip()}",
            "Remediation rolled back. Finding remains OPEN.",
            "success",
        )

    try:
        _guard_origin(request)
        return run()
    except LifecycleError as exc:
        return _redirect(
            f"/assessment/control/{control_id.strip()}?run={run_id.strip()}",
            str(exc),
            "error",
        )
    except (WorkflowError, RegistryServiceError) as exc:
        return _redirect("/remediation", str(exc), "error")


@app.post("/actions/lifecycle/analyse-evidence")
async def action_analyse_evidence(
    request: Request,
    run_id: str = Form(...),
    control_id: str = Form(...),
    description: str = Form(""),
    comments: str = Form(""),
) -> Response:
    """Submit human evidence and run the mock EvidenceAnalyzer."""
    form = await request.form()
    files: list[tuple[str, bytes, str]] = []
    for key, value in form.multi_items():
        if key != "attachments":
            continue
        if not hasattr(value, "read") or not getattr(value, "filename", None):
            continue
        content = await value.read()
        files.append(
            (
                value.filename,
                content,
                getattr(value, "content_type", None) or "application/octet-stream",
            )
        )

    def run() -> RedirectResponse:
        entry = analyse_evidence(
            run_id.strip(),
            control_id.strip(),
            description=description,
            comments=comments,
            files=files,
        )
        try:
            refresh_reports(run_id.strip())
        except Exception:
            pass
        decision = ""
        if entry.last_analysis:
            decision = entry.last_analysis.resolve_final().value
        msg = f"Evidence analysed: {decision}." if decision else "Evidence analysed."
        return _redirect(
            f"/assessment/control/{control_id.strip()}?run={run_id.strip()}",
            msg,
            "success",
        )

    try:
        _guard_origin(request)
        return run()
    except LifecycleError as exc:
        return _redirect(
            f"/assessment/control/{control_id.strip()}?run={run_id.strip()}",
            str(exc),
            "error",
        )