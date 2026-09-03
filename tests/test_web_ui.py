"""Route smoke tests for the local web UI.

Skipped when the optional ``ui`` extra is not installed, so ``pip install -e ".[dev]"``
and the existing Flow 1–4 suite stay untouched.
"""

from __future__ import annotations

from urllib.parse import unquote_plus

import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("jinja2")

from fastapi.testclient import TestClient

from src.config import ASSESSMENTS_DIR, EVIDENCE_DIR
from src.services import context
from src.services.workflow import clear_validation
from src.web.app import app
from src.web.glossary import explain

client = TestClient(app)

DEMO_RUN = "RUN-DEMO-0001"


def _demo_available() -> bool:
    return (EVIDENCE_DIR / DEMO_RUN / "evidence.json").exists() and (
        ASSESSMENTS_DIR / DEMO_RUN / "assessment.json"
    ).exists()


requires_demo = pytest.mark.skipif(
    not _demo_available(),
    reason="Demo run artifacts not present on disk",
)


def test_assessment_home_renders_summary() -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "CRA Readiness Assessment" in body
    assert "Assessment" in body
    assert "Sources &amp; Registry" in body
    assert "Findings" in body


def test_docs_and_openapi_are_disabled() -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/controls",
        "/findings",
        "/registry",
        "/evidence",
        "/assessment",
        "/remediation",
        "/reports",
        "/audit",
        "/settings",
    ],
)
def test_primary_pages_ok(path: str) -> None:
    response = client.get(path, follow_redirects=True)
    assert response.status_code == 200, path
    assert "NetBoss-XT CRA" in response.text


@requires_demo
def test_registry_control_detail() -> None:
    response = client.get("/registry/control/NMS-CRA-0003")
    assert response.status_code == 200
    assert "How this control was derived" in response.text
    assert "CRA requirement" in response.text
    assert "Evidence plan" in response.text


@requires_demo
def test_assessment_control_detail() -> None:
    response = client.get(f"/assessment/control/NMS-CRA-0005?run={DEMO_RUN}")
    assert response.status_code == 200
    assert "Requirement" in response.text
    assert "Evidence" in response.text
    assert "Status" in response.text


@requires_demo
def test_assessment_home_shows_target_env_scope() -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "Target Env" in body
    assert "NetBoss-XT" in body
    assert "Assessment done on Target Env:" in body or "CRA Readiness Assessment" in body


@requires_demo
def test_remediation_page_offers_applications() -> None:
    response = client.get("/remediation")
    assert response.status_code == 200
    body = response.text
    assert "Target Env" in body
    assert "Router Monitor" in body
    assert "Switch Monitor" in body
    assert "SBC Monitor" in body
    assert "Mock environment" not in body


@requires_demo
def test_assessment_home_shows_lifecycle_tiles() -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "Human Review" in body or "Passed" in body
    assert "Remediation Pending" in body or "CRA Readiness" in body


@requires_demo
def test_evidence_item_detail() -> None:
    response = client.get(f"/evidence/{DEMO_RUN}/EV-0001")
    assert response.status_code == 200
    assert "Normalized evidence" in response.text
    assert "Related controls" in response.text


@requires_demo
def test_run_report_viewer() -> None:
    response = client.get(f"/runs/{DEMO_RUN}")
    assert response.status_code == 200
    for heading in ("Findings", "Remediation", "Overall Status"):
        assert heading in response.text


@requires_demo
def test_findings_page_lists_control_and_asset() -> None:
    response = client.get(f"/findings?run={DEMO_RUN}")
    assert response.status_code == 200
    assert "Control" in response.text
    assert "Asset" in response.text


@requires_demo
def test_artifact_download_is_allowlisted() -> None:
    allowed = client.get(f"/runs/{DEMO_RUN}/artifact/assessment.json")
    assert allowed.status_code == 200
    assert allowed.headers["content-type"].startswith("application/json")

    unknown = client.get(f"/runs/{DEMO_RUN}/artifact/secret.json")
    assert unknown.status_code == 404

    traversed = client.get(f"/runs/{DEMO_RUN}/artifact/../../pyproject.toml")
    assert "requires-python" not in traversed.text


def test_unknown_control_is_a_page_not_a_stack_trace() -> None:
    response = client.get("/registry/control/DOES-NOT-EXIST")
    assert response.status_code == 200
    assert (
        "No control" in response.text
        or "Cannot continue" in response.text
        or "not found" in response.text.lower()
    )


def test_approve_without_validation_is_refused() -> None:
    clear_validation()
    response = client.post(
        "/actions/registry/approve",
        data={"approver": "Test", "version": "9.9.9"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    location = unquote_plus(response.headers["location"])
    assert "/registry" in location


def test_evidence_page_offers_applications_not_mock_environments() -> None:
    response = client.get("/evidence")
    assert response.status_code == 200
    body = response.text
    assert "Target Env" in body
    assert "Application" in body
    assert "Router Monitor" in body
    assert "Switch Monitor" in body
    assert "SBC Monitor" in body
    assert "Mock environment" not in body
    assert "NetBoss-XT" in body


def test_unknown_application_is_refused() -> None:
    response = client.post(
        "/actions/evidence/collect",
        data={
            "target": "nextboss-demo.mock.json",
            "application": "not-an-app",
            "chain": "evidence",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "Unknown application" in unquote_plus(response.headers["location"])


@requires_demo
def test_verification_refuses_a_run_compared_with_itself() -> None:
    response = client.post(
        "/actions/verification/run",
        data={"previous_run": DEMO_RUN, "new_run": DEMO_RUN},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "itself" in unquote_plus(response.headers["location"])


@requires_demo
def test_controls_filter_by_status() -> None:
    response = client.get(f"/controls?run={DEMO_RUN}&status=FAIL")
    assert response.status_code == 200
    assert "Apply" in response.text


def test_home_has_no_overview_charts() -> None:
    response = client.get("/")
    assert "Assessment verdict distribution" not in response.text
    assert "Next recommended action" not in response.text


def test_why_glossary_covers_core_terms() -> None:
    for term in (
        "PASS",
        "FAIL",
        "INSUFFICIENT_EVIDENCE",
        "HUMAN_REVIEW_REQUIRED",
        "MOCK",
        "VERIFIED_CLOSED",
        "APPLIED_UNVERIFIED",
        "AWAITING_APPROVAL",
        "PROPOSED",
        "BLOCKED",
        "ROLLED_BACK",
    ):
        assert explain(term), term


def test_audit_page_renders() -> None:
    response = client.get("/audit")
    assert response.status_code == 200
    body = response.text
    assert "Assessment baseline" in body
    assert "Remediation approvals" in body


def test_workspace_next_action_is_deterministic() -> None:
    ctx = context.workspace()
    assert ctx.next_action is not None
    assert ctx.next_action.href.startswith("/")
    assert ctx.registry.status in {"APPROVED", "DRAFT", "NONE"}
    assert ctx.stage in {key for key, _ in context.STAGES}


def test_settings_exposes_no_credentials() -> None:
    response = client.get("/settings")
    assert response.status_code == 200
    lowered = response.text.lower()
    assert "password" not in lowered
    assert "private key" not in lowered
    assert "Infrastructure MCP" in response.text
    assert "get_tls_configuration" in response.text
