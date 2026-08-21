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

from src.services import context
from src.services.workflow import clear_validation
from src.web.app import app
from src.web.glossary import explain

client = TestClient(app)


def test_overview_renders_workspace() -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "NextBoss-XT CRA Technical Readiness" in body
    assert "Next recommended action" in body
    assert "SYNTHETIC / MOCK DATA" in body
    assert "Overview" in body
    assert "Sources &amp; Registry" in body


def test_docs_and_openapi_are_disabled() -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


@pytest.mark.parametrize(
    "path",
    [
        "/registry",
        "/evidence",
        "/assessment",
        "/remediation",
        "/reports",
        "/settings",
    ],
)
def test_primary_pages_ok(path: str) -> None:
    response = client.get(path)
    assert response.status_code == 200, path
    assert "NextBoss-XT CRA" in response.text


def test_registry_control_detail() -> None:
    response = client.get("/registry/control/NMS-CRA-0003")
    assert response.status_code == 200
    assert "How this control was derived" in response.text
    assert "CRA requirement" in response.text
    assert "Evidence plan" in response.text


def test_assessment_control_detail() -> None:
    response = client.get("/assessment/control/NMS-CRA-0005?run=RUN-DEMO-0001")
    assert response.status_code == 200
    assert "Expected vs observed" in response.text
    assert "Why this result occurred" in response.text
    assert "FAIL" in response.text


def test_evidence_item_detail() -> None:
    response = client.get("/evidence/RUN-DEMO-0001/EV-0001")
    assert response.status_code == 200
    assert "Normalized evidence" in response.text
    assert "Related controls" in response.text


def test_run_report_viewer() -> None:
    response = client.get("/runs/RUN-DEMO-0001")
    assert response.status_code == 200
    for heading in (
        "Executive summary",
        "What was assessed",
        "Assessment results",
        "Evidence gaps",
        "Human review required",
        "Open findings",
        "Recommended remediation",
        "Verification status",
        "Technical traceability",
        "Limitations",
    ):
        assert heading in response.text


def test_artifact_download_is_allowlisted() -> None:
    allowed = client.get("/runs/RUN-DEMO-0001/artifact/assessment.json")
    assert allowed.status_code == 200
    assert allowed.headers["content-type"].startswith("application/json")

    unknown = client.get("/runs/RUN-DEMO-0001/artifact/secret.json")
    assert unknown.status_code == 404

    # Starlette normalises ".." before the route runs, so this becomes a
    # different page rather than an arbitrary file. Either way the project
    # file must not be served.
    traversed = client.get("/runs/RUN-DEMO-0001/artifact/../../pyproject.toml")
    assert "requires-python" not in traversed.text


def test_unknown_control_is_a_page_not_a_stack_trace() -> None:
    response = client.get("/registry/control/DOES-NOT-EXIST")
    assert response.status_code == 200
    assert "No control" in response.text


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
    assert "Validate" in location


def test_registry_page_exposes_allow_conflicts() -> None:
    response = client.get("/registry")
    assert response.status_code == 200
    body = response.text
    assert 'name="allow_conflicts"' in body
    assert "Allow unresolved conflicts" in body
    assert "--allow-conflicts" in body


def test_unknown_target_is_refused() -> None:
    response = client.post(
        "/actions/evidence/collect",
        data={"target": "not-a-real-target.json", "chain": "evidence"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "Unknown target" in unquote_plus(response.headers["location"])


def test_verification_refuses_a_run_compared_with_itself() -> None:
    response = client.post(
        "/actions/verification/run",
        data={"previous_run": "RUN-DEMO-0001", "new_run": "RUN-DEMO-0001"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "itself" in unquote_plus(response.headers["location"])


def test_verdict_filter_narrows_assessment_table() -> None:
    response = client.get("/assessment?run=RUN-DEMO-0001&verdict=FAIL")
    assert response.status_code == 200
    assert "NMS-CRA-0005" in response.text
    assert "Apply" in response.text


def test_overview_charts_are_svg() -> None:
    response = client.get("/")
    assert "<svg" in response.text
    assert "Assessment verdict distribution" in response.text
    assert "Evidence collection health" in response.text


def test_why_glossary_covers_core_terms() -> None:
    for term in (
        "PASS",
        "FAIL",
        "INSUFFICIENT_EVIDENCE",
        "HUMAN_REVIEW_REQUIRED",
        "MOCK",
        "VERIFIED_CLOSED",
    ):
        assert explain(term), term


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
