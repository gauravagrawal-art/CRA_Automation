"""Tests for the normalized compliance view and MockComplianceProvider."""

from __future__ import annotations

import pytest

from src.assessment.models import Verdict
from src.assessment.runner import assess
from src.compliance.applicability import (
    applicable_asset_types,
    applicable_assets,
    mock_assets,
    primary_asset,
)
from src.compliance.models import AssetType, DisplaySeverity, OverallStatus, UIStatus
from src.compliance.mock_provider import MockComplianceProvider
from src.compliance.status import map_verdict, overall_status
from src.config import PROJECT_ROOT
from src.evidence.runner import collect_evidence
from src.registry.versioning import latest_approved_path
from src.remediation.runner import remediate

APPROVED_PATH = latest_approved_path()
TARGET_PATH = PROJECT_ROOT / "targets" / "nextboss-demo.mock.json"
FIXED_TIME = "2026-08-20T12:00:00+00:00"


def test_map_verdict_collapses_engine_statuses() -> None:
    assert map_verdict(Verdict.PASS) is UIStatus.PASS
    assert map_verdict(Verdict.FAIL) is UIStatus.FAIL
    assert map_verdict(Verdict.PARTIAL) is UIStatus.FAIL
    assert map_verdict(Verdict.INSUFFICIENT_EVIDENCE) is UIStatus.REVIEW
    assert map_verdict(Verdict.HUMAN_REVIEW_REQUIRED) is UIStatus.REVIEW
    assert map_verdict(Verdict.NOT_APPLICABLE) is UIStatus.NOT_APPLICABLE


def test_overall_status_priority() -> None:
    assert overall_status(failed=0, review=0, assessed=False) is OverallStatus.NOT_ASSESSED
    assert overall_status(failed=1, review=5, assessed=True) is OverallStatus.NEEDS_ATTENTION
    assert overall_status(failed=0, review=2, assessed=True) is OverallStatus.NEEDS_REVIEW
    assert overall_status(failed=0, review=0, assessed=True) is OverallStatus.READY
    assert (
        overall_status(failed=0, review=0, assessed=True, remediation_pending=2)
        is OverallStatus.NEEDS_ATTENTION
    )


def test_mock_assets_include_network_devices() -> None:
    assets = mock_assets()
    types = {a.type for a in assets}
    assert AssetType.APPLICATION_SERVER in types
    assert AssetType.SWITCH in types
    assert AssetType.ROUTER in types
    assert AssetType.FIREWALL in types
    assert AssetType.DATABASE in types
    switch = next(a for a in assets if a.type is AssetType.SWITCH)
    assert switch.operating_system is None
    assert switch.hostname


def test_tls_control_applies_to_https_management_assets() -> None:
    control = {
        "control_id": "NMS-TLS",
        "title": "TLS configuration",
        "technical_control": "Verify TLS on management HTTPS",
        "evidence_plan": [{"evidence_key": "tls", "mcp_tool": "get_tls_configuration"}],
    }
    types = applicable_asset_types(control)
    assert AssetType.APPLICATION_SERVER in types
    assert AssetType.SWITCH in types
    assets = applicable_assets(control, mock_assets())
    assert assets
    assert all(a.type in types for a in assets)


def test_database_control_does_not_apply_to_switches() -> None:
    control = {
        "control_id": "NMS-DB",
        "title": "PostgreSQL listener security",
        "technical_control": "Restrict database port 5432",
        "evidence_plan": [{"evidence_key": "postgres", "mcp_tool": "get_open_ports"}],
    }
    assets = applicable_assets(control, mock_assets())
    assert all(a.type is AssetType.DATABASE for a in assets)
    primary = primary_asset(control, mock_assets())
    assert primary is not None
    assert primary.type is AssetType.DATABASE


@pytest.fixture(scope="module")
def compliance_view(tmp_path_factory):
    """Build a vulnerable assessment + remediation into a temp tree, then project it."""
    if APPROVED_PATH is None:
        pytest.skip("approved registry required")
    root = tmp_path_factory.mktemp("compliance-view")
    evidence_dir = root / "evidence"
    assessments_dir = root / "assessments"
    run_id = "RUN-COMPLIANCE-VIEW"

    collect_evidence(
        registry_path=APPROVED_PATH,
        target_path=TARGET_PATH,
        output_dir=evidence_dir,
        run_id=run_id,
        scenario_override="vulnerable",
        clock=lambda: FIXED_TIME,
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

    # Point the runs_service loaders at the temp tree via provider.from_artifacts.
    from src.assessment.models import Assessment
    from src.evidence.models import EvidenceRun
    from src.remediation.models import RemediationDocument
    import json

    assessment = Assessment.model_validate(
        json.loads((assessments_dir / run_id / "assessment.json").read_text())
    )
    evidence = EvidenceRun.model_validate(
        json.loads((evidence_dir / run_id / "evidence.json").read_text())
    )
    remediation = RemediationDocument.model_validate(
        json.loads((assessments_dir / run_id / "remediation.json").read_text())
    )
    return MockComplianceProvider().from_artifacts(
        assessment=assessment,
        evidence=evidence,
        remediation=remediation,
    )


def test_provider_builds_view_without_inventing_evidence(compliance_view) -> None:
    view = compliance_view
    assert view.assets
    assert view.controls
    assert view.summary.controls_assessed == len(view.controls)
    assert view.summary.overall_status is OverallStatus.NEEDS_ATTENTION
    known_ids = set()
    for control in view.controls:
        known_ids.update(control.evidence_ids)
        assert control.requirement
        if control.status is UIStatus.FAIL:
            assert control.finding
            assert control.remediation
    for finding in view.findings:
        for eid in finding.evidence_ids:
            assert eid in known_ids or eid.startswith("EV-")


def test_remediation_traceability_to_control_and_asset(compliance_view) -> None:
    view = compliance_view
    assert view.remediations
    control_ids = {c.control_id for c in view.controls}
    asset_ids = {a.asset_id for a in view.assets}
    for item in view.remediations:
        assert item.control_id in control_ids
        assert item.asset_id in asset_ids
        assert item.asset_name
        assert item.issue or item.recommended_action


def test_top_findings_prefer_failures(compliance_view) -> None:
    view = compliance_view
    assert view.top_findings
    for finding in view.top_findings:
        assert finding.status is UIStatus.FAIL
        assert finding.severity in {
            DisplaySeverity.CRITICAL,
            DisplaySeverity.HIGH,
            DisplaySeverity.MEDIUM,
            DisplaySeverity.LOW,
        }
