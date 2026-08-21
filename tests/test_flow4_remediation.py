"""Flow 4 — preflight integrity, remediation composition, closure and report."""

from __future__ import annotations

import copy
import json
from html.parser import HTMLParser
from pathlib import Path

import pytest

from src.assessment.models import (
    Assessment,
    ControlResult,
    EvidenceGap,
    RuleTraceEntry,
    Verdict,
)
from src.assessment.runner import assess
from src.config import PROJECT_ROOT
from src.evidence.runner import collect_evidence
from src.registry.versioning import latest_approved_path
from src.remediation.composer import compose, compose_item
from src.remediation.models import (
    ActionType,
    RemediationDocument,
    RemediationReasonCode,
    RemediationStatus,
    VerificationOutcome,
    VerificationReasonCode,
    make_remediation_id,
)
from src.remediation.preflight import RemediationPreflightError, remediation_preflight
from src.remediation.report import MOCK_BANNER, render_final_html
from src.remediation.runner import build_remediation, remediate, verify_runs
from src.remediation.verification import verify

APPROVED_PATH = latest_approved_path()
DRAFT_PATH = PROJECT_ROOT / "registry" / "controls.draft.json"
TARGET_PATH = PROJECT_ROOT / "targets" / "nextboss-demo.mock.json"

FIXED_TIME = "2026-08-20T12:00:00+00:00"

#: A control the vulnerable scenario fails and the compliant scenario passes.
CLOSABLE_CONTROL = "NMS-CRA-0006"

#: Characters and verbs that would indicate a generated implementation command.
EXECUTABLE_MARKERS = ["|", ";", "&&", "`", "$(", ">", "sudo ", "systemctl ", "chmod ", "rm "]


def fixed_clock() -> str:
    return FIXED_TIME


# --- Fixtures ---------------------------------------------------------------


@pytest.fixture(scope="module")
def runs(tmp_path_factory) -> dict[str, Path]:
    """A vulnerable run and a compliant run, each collected and assessed."""
    assert APPROVED_PATH is not None, "an approved registry is required for Flow 4 tests"
    evidence_dir = tmp_path_factory.mktemp("flow4-evidence")
    assessments_dir = tmp_path_factory.mktemp("flow4-assessments")
    for scenario in ("vulnerable", "compliant"):
        run_id = f"RUN-F4-{scenario.upper()}"
        collect_evidence(
            registry_path=APPROVED_PATH,
            target_path=TARGET_PATH,
            output_dir=evidence_dir,
            run_id=run_id,
            scenario_override=scenario,
            clock=fixed_clock,
        )
        assess(
            run_id=run_id,
            registry_path=APPROVED_PATH,
            evidence_dir=evidence_dir,
            output_dir=assessments_dir,
            clock=fixed_clock,
        )
    return {"evidence": evidence_dir, "assessments": assessments_dir}


@pytest.fixture(scope="module")
def registry(runs) -> dict:
    return json.loads(APPROVED_PATH.read_text())


@pytest.fixture(scope="module")
def vulnerable_assessment(runs) -> Assessment:
    return _load_assessment(runs, "RUN-F4-VULNERABLE")


@pytest.fixture(scope="module")
def compliant_assessment(runs) -> Assessment:
    return _load_assessment(runs, "RUN-F4-COMPLIANT")


@pytest.fixture(scope="module")
def vulnerable_remediation(runs) -> RemediationDocument:
    _, remediation = remediate(
        run_id="RUN-F4-VULNERABLE",
        registry_path=APPROVED_PATH,
        evidence_dir=runs["evidence"],
        assessments_dir=runs["assessments"],
        clock=fixed_clock,
    )
    return remediation


# --- Helpers ----------------------------------------------------------------


def _load_assessment(runs, run_id: str) -> Assessment:
    path = runs["assessments"] / run_id / "assessment.json"
    return Assessment.model_validate(json.loads(path.read_text()))


def _control(registry: dict, control_id: str) -> dict:
    return next(c for c in registry["controls"] if c["control_id"] == control_id)


def _result(assessment: Assessment, control_id: str) -> ControlResult:
    return next(r for r in assessment.results if r.control_id == control_id)


def _item(remediation: RemediationDocument, control_id: str):
    return next(i for i in remediation.items if i.finding_control_id == control_id)


def _first_failing(assessment: Assessment) -> ControlResult:
    return next(r for r in assessment.results if r.verdict == Verdict.FAIL)


def _tampered_assessment(runs, run_id: str, tmp_path: Path, mutate) -> Path:
    """Copy an assessment into ``tmp_path`` with ``mutate`` applied."""
    source = runs["assessments"] / run_id / "assessment.json"
    data = json.loads(source.read_text())
    mutate(data)
    path = tmp_path / "assessment.json"
    path.write_text(json.dumps(data, indent=2, sort_keys=True))
    return path


def _preflight(runs, assessment_path: Path, run_id: str = "RUN-F4-VULNERABLE"):
    return remediation_preflight(
        registry_path=APPROVED_PATH,
        assessment_path=assessment_path,
        evidence_path=runs["evidence"] / run_id / "evidence.json",
    )


def _synthetic_result(verdict: Verdict, **overrides) -> ControlResult:
    payload = {
        "control_id": CLOSABLE_CONTROL,
        "title": "synthetic control",
        "verdict": verdict,
        "evaluation_mode": "DETERMINISTIC",
        "reason": "synthetic reason",
        "observed_state": "synthetic observation",
        "evidence_ids": ["EV-0001"],
    }
    payload.update(overrides)
    return ControlResult(**payload)


def _compose_one(result: ControlResult, control: dict):
    return compose_item(
        result,
        control,
        assessment_id="ASSESS-test",
        run_id="RUN-F4-VULNERABLE",
        target_id="nextboss-demo",
        registry_version="1.1.0",
        registry_hash="a" * 64,
    )


def _copy_baseline(tmp_path: Path) -> Path:
    """A writable copy of the approved registry and its manifest, for tampering."""
    registry_path = tmp_path / APPROVED_PATH.name
    registry_path.write_text(APPROVED_PATH.read_text())
    manifest = APPROVED_PATH.with_name(APPROVED_PATH.stem + ".manifest.json")
    if manifest.exists():
        (tmp_path / manifest.name).write_text(manifest.read_text())
    return registry_path


# --- Preflight integrity ----------------------------------------------------


def test_rejects_draft_registry(runs):
    with pytest.raises(RemediationPreflightError, match="APPROVED"):
        remediation_preflight(
            registry_path=DRAFT_PATH,
            assessment_path=runs["assessments"] / "RUN-F4-VULNERABLE" / "assessment.json",
            evidence_path=runs["evidence"] / "RUN-F4-VULNERABLE" / "evidence.json",
        )


def test_rejects_tampered_registry_hash(runs, tmp_path):
    registry_path = _copy_baseline(tmp_path)
    data = json.loads(registry_path.read_text())
    data["controls"][0]["title"] = "tampered after approval"
    registry_path.write_text(json.dumps(data, indent=2))

    with pytest.raises(RemediationPreflightError, match="does not match its manifest"):
        remediation_preflight(
            registry_path=registry_path,
            assessment_path=runs["assessments"] / "RUN-F4-VULNERABLE" / "assessment.json",
            evidence_path=runs["evidence"] / "RUN-F4-VULNERABLE" / "evidence.json",
        )


def test_assessment_registry_hash_mismatch_aborts(runs, tmp_path):
    path = _tampered_assessment(
        runs,
        "RUN-F4-VULNERABLE",
        tmp_path,
        lambda d: d["metadata"].update({"registry_hash": "0" * 64}),
    )
    with pytest.raises(RemediationPreflightError, match="different registry"):
        _preflight(runs, path)


def test_assessment_registry_version_mismatch_aborts(runs, tmp_path):
    path = _tampered_assessment(
        runs,
        "RUN-F4-VULNERABLE",
        tmp_path,
        lambda d: d["metadata"].update({"registry_version": "0.0.1"}),
    )
    with pytest.raises(RemediationPreflightError, match="registry version"):
        _preflight(runs, path)


def test_evidence_hash_mismatch_aborts(runs, tmp_path):
    path = _tampered_assessment(
        runs,
        "RUN-F4-VULNERABLE",
        tmp_path,
        lambda d: d["metadata"].update({"evidence_sha256": "0" * 64}),
    )
    with pytest.raises(RemediationPreflightError, match="different evidence bytes"):
        _preflight(runs, path)


def test_run_mismatch_aborts(runs, tmp_path):
    path = _tampered_assessment(
        runs,
        "RUN-F4-VULNERABLE",
        tmp_path,
        lambda d: d["metadata"].update({"run_id": "RUN-SOMETHING-ELSE"}),
    )
    with pytest.raises(RemediationPreflightError, match="run ID"):
        _preflight(runs, path)


def test_target_mismatch_aborts(runs, tmp_path):
    path = _tampered_assessment(
        runs,
        "RUN-F4-VULNERABLE",
        tmp_path,
        lambda d: d["metadata"].update({"target_id": "some-other-host"}),
    )
    with pytest.raises(RemediationPreflightError, match="target"):
        _preflight(runs, path)


def test_unsupported_assessment_schema_version_aborts(runs, tmp_path):
    path = _tampered_assessment(
        runs,
        "RUN-F4-VULNERABLE",
        tmp_path,
        lambda d: d["metadata"].update({"schema_version": "9.9"}),
    )
    with pytest.raises(RemediationPreflightError, match="schema version"):
        _preflight(runs, path)


def test_unknown_control_id_aborts(runs, tmp_path):
    def mutate(data):
        data["results"][0]["control_id"] = "NMS-CRA-9999"

    path = _tampered_assessment(runs, "RUN-F4-VULNERABLE", tmp_path, mutate)
    with pytest.raises(RemediationPreflightError, match="NMS-CRA-9999"):
        _preflight(runs, path)


def test_malformed_assessment_aborts(runs, tmp_path):
    path = tmp_path / "assessment.json"
    path.write_text("{not json")
    with pytest.raises(RemediationPreflightError, match="not valid JSON"):
        _preflight(runs, path)


def test_missing_assessment_aborts(runs, tmp_path):
    with pytest.raises(RemediationPreflightError, match="not found"):
        _preflight(runs, tmp_path / "absent.json")


def test_evidence_from_another_run_aborts(runs, tmp_path):
    """The Flow 3 preflight failure is surfaced, not swallowed."""
    with pytest.raises(RemediationPreflightError):
        remediation_preflight(
            registry_path=APPROVED_PATH,
            assessment_path=runs["assessments"] / "RUN-F4-VULNERABLE" / "assessment.json",
            evidence_path=runs["evidence"] / "RUN-F4-COMPLIANT" / "evidence.json",
        )


# --- Remediation composition ------------------------------------------------


def test_fail_produces_technical_remediation(vulnerable_assessment, vulnerable_remediation):
    failing = _first_failing(vulnerable_assessment)
    item = _item(vulnerable_remediation, failing.control_id)
    assert item.action_type == ActionType.TECHNICAL_REMEDIATION
    assert item.finding_verdict == Verdict.FAIL
    assert item.status == RemediationStatus.OPEN
    assert item.failed_rule_refs
    assert item.evidence_ids == failing.evidence_ids


def test_pass_produces_no_item(compliant_assessment, registry):
    result = _synthetic_result(Verdict.PASS)
    assert _compose_one(result, _control(registry, CLOSABLE_CONTROL)) is None
    passing = [r.control_id for r in compliant_assessment.results if r.verdict == Verdict.PASS]
    assert passing, "the compliant scenario should pass at least one control"
    items = compose(compliant_assessment, registry)
    assert not [i for i in items if i.finding_control_id in passing]


def test_not_applicable_produces_no_item(registry):
    result = _synthetic_result(Verdict.NOT_APPLICABLE)
    assert _compose_one(result, _control(registry, CLOSABLE_CONTROL)) is None


def test_partial_produces_technical_remediation(registry):
    """PARTIAL is only reachable through an approved ``partial_when`` condition."""
    result = _synthetic_result(
        Verdict.PARTIAL,
        evaluator_trace=[
            RuleTraceEntry(
                rule={"path": "tls_configuration.protocols.TLSv1_0", "operator": "EQ", "value": False},
                observed=True,
                matched=False,
                evidence_ids=["EV-0001"],
            )
        ],
    )
    item = _compose_one(result, _control(registry, CLOSABLE_CONTROL))
    assert item.action_type == ActionType.TECHNICAL_REMEDIATION
    assert item.finding_verdict == Verdict.PARTIAL
    assert item.failed_rule_refs == ["tls_configuration.protocols.TLSv1_0 EQ false"]


def test_insufficient_evidence_produces_evidence_resolution(registry):
    result = _synthetic_result(
        Verdict.INSUFFICIENT_EVIDENCE,
        evidence_gaps=[
            EvidenceGap(
                evidence_key="application_config",
                status="NOT_COLLECTED",
                reason_code="PARAMETER_UNRESOLVED",
            )
        ],
    )
    item = _compose_one(result, _control(registry, CLOSABLE_CONTROL))
    assert item.action_type == ActionType.EVIDENCE_RESOLUTION
    assert item.missing_evidence_keys == ["application_config"]
    assert item.reason_code == RemediationReasonCode.REQUIRED_EVIDENCE_NOT_COLLECTED
    assert item.recommendation == ""


def test_evidence_collection_error_is_distinguished(registry):
    result = _synthetic_result(
        Verdict.INSUFFICIENT_EVIDENCE,
        evidence_gaps=[
            EvidenceGap(
                evidence_key="ssh_config",
                status="PERMISSION_DENIED",
                reason_code="PERMISSION_DENIED",
            )
        ],
    )
    item = _compose_one(result, _control(registry, CLOSABLE_CONTROL))
    assert item.reason_code == RemediationReasonCode.EVIDENCE_COLLECTION_ERROR


def test_human_review_required_produces_review_action(
    vulnerable_assessment, vulnerable_remediation
):
    reviewed = next(
        r for r in vulnerable_assessment.results if r.verdict == Verdict.HUMAN_REVIEW_REQUIRED
    )
    item = _item(vulnerable_remediation, reviewed.control_id)
    assert item.action_type == ActionType.HUMAN_REVIEW
    assert item.reason_code == RemediationReasonCode.HUMAN_DECISION_REQUIRED
    assert item.recommendation == ""
    assert item.verification is None


def test_missing_seed_yields_human_review_not_invented_fix(registry):
    control = copy.deepcopy(_control(registry, CLOSABLE_CONTROL))
    control["remediation_seed"] = {"recommendation": "", "verification_evidence_keys": []}
    item = _compose_one(_synthetic_result(Verdict.FAIL), control)
    assert item.action_type == ActionType.HUMAN_REVIEW
    assert item.reason_code == RemediationReasonCode.REMEDIATION_GUIDANCE_NOT_APPROVED
    assert item.recommendation == ""


def test_recommendations_are_verbatim_registry_seeds(vulnerable_remediation, registry):
    technical = [
        i for i in vulnerable_remediation.items
        if i.action_type == ActionType.TECHNICAL_REMEDIATION
    ]
    assert technical, "the vulnerable scenario should fail at least one control"
    for item in technical:
        seed = _control(registry, item.finding_control_id)["remediation_seed"]
        assert item.recommendation == seed["recommendation"]
        assert item.recommendation_source == "APPROVED_REGISTRY_REMEDIATION_SEED"


def test_no_executable_remediation_is_generated(vulnerable_remediation):
    for item in vulnerable_remediation.items:
        assert item.automatic_execution is False
        assert item.implementation_owner == "SYSTEM_OWNER"
        for marker in EXECUTABLE_MARKERS:
            assert marker not in item.recommendation


def test_verification_requirement_comes_from_the_registry(vulnerable_remediation, registry):
    item = next(
        i for i in vulnerable_remediation.items
        if i.action_type == ActionType.TECHNICAL_REMEDIATION
    )
    control = _control(registry, item.finding_control_id)
    plan_tools = {e["mcp_tool"] for e in control["evidence_plan"] if e["mcp_tool"]}
    requirement = item.verification
    assert requirement.control_id == item.finding_control_id
    assert requirement.evidence_keys == control["remediation_seed"]["verification_evidence_keys"]
    assert set(requirement.mcp_tools) <= plan_tools
    assert requirement.required_post_verdict == "PASS"
    assert requirement.same_target_required is True
    assert requirement.registry_hash == vulnerable_remediation.metadata.registry_hash


def test_summary_counts_match_items(vulnerable_remediation, vulnerable_assessment):
    summary = vulnerable_remediation.summary
    assert summary.controls_assessed == len(vulnerable_assessment.results)
    assert summary.items_total == len(vulnerable_remediation.items)
    assert sum(summary.by_action_type.values()) == summary.items_total
    assert summary.by_status[RemediationStatus.OPEN.value] == summary.items_total
    assert (
        summary.controls_without_action
        == summary.controls_assessed - summary.items_total
    )


def test_remediation_ids_are_deterministic(vulnerable_remediation):
    for item in vulnerable_remediation.items:
        assert item.remediation_id == make_remediation_id(
            item.assessment_id, item.finding_control_id, item.action_type
        )


def test_remediation_is_reproducible(runs, vulnerable_remediation):
    out_dir, again = remediate(
        run_id="RUN-F4-VULNERABLE",
        registry_path=APPROVED_PATH,
        evidence_dir=runs["evidence"],
        assessments_dir=runs["assessments"],
        clock=fixed_clock,
    )
    assert again.model_dump(mode="json") == vulnerable_remediation.model_dump(mode="json")
    assert (out_dir / "remediation.json").exists()
    assert (out_dir / "final-report.html").exists()


def test_remediation_does_not_modify_its_inputs(runs):
    assessment_path = runs["assessments"] / "RUN-F4-VULNERABLE" / "assessment.json"
    evidence_path = runs["evidence"] / "RUN-F4-VULNERABLE" / "evidence.json"
    before = (assessment_path.read_bytes(), evidence_path.read_bytes())

    remediate(
        run_id="RUN-F4-VULNERABLE",
        registry_path=APPROVED_PATH,
        evidence_dir=runs["evidence"],
        assessments_dir=runs["assessments"],
        clock=fixed_clock,
    )

    assert (assessment_path.read_bytes(), evidence_path.read_bytes()) == before


# --- Verification and closure -----------------------------------------------


def test_new_pass_closes_previous_finding(vulnerable_assessment, compliant_assessment):
    document = verify(vulnerable_assessment, compliant_assessment, generated_at=FIXED_TIME)
    assert document.baseline_comparable is True
    closed = next(i for i in document.items if i.control_id == CLOSABLE_CONTROL)
    assert closed.outcome == VerificationOutcome.VERIFIED_CLOSED
    assert closed.previous_verdict == Verdict.FAIL
    assert closed.new_verdict == Verdict.PASS
    assert closed.new_evidence_ids
    assert closed.previous_remediation_id


def test_recommendation_alone_cannot_close_a_finding(vulnerable_remediation):
    assert vulnerable_remediation.verification is None
    assert all(i.status == RemediationStatus.OPEN for i in vulnerable_remediation.items)
    assert vulnerable_remediation.summary.by_status[RemediationStatus.VERIFIED_CLOSED.value] == 0


def test_same_run_cannot_close_a_finding(vulnerable_assessment):
    document = verify(vulnerable_assessment, vulnerable_assessment, generated_at=FIXED_TIME)
    assert document.baseline_comparable is False
    assert document.blocked_reason_code == VerificationReasonCode.NOT_A_NEW_SCAN
    assert document.summary.verified_closed == 0
    assert all(
        i.outcome == VerificationOutcome.VERIFICATION_BLOCKED for i in document.items
    )


def test_different_target_cannot_close_a_finding(vulnerable_assessment, compliant_assessment):
    other = compliant_assessment.model_copy(deep=True)
    other.metadata.target_id = "some-other-host"
    document = verify(vulnerable_assessment, other, generated_at=FIXED_TIME)
    assert document.blocked_reason_code == VerificationReasonCode.TARGET_MISMATCH
    assert document.summary.verified_closed == 0


def test_registry_baseline_change_blocks_verification(
    vulnerable_assessment, compliant_assessment
):
    other = compliant_assessment.model_copy(deep=True)
    other.metadata.registry_hash = "0" * 64
    document = verify(vulnerable_assessment, other, generated_at=FIXED_TIME)
    assert document.blocked_reason_code == VerificationReasonCode.REGISTRY_BASELINE_CHANGED
    assert document.summary.verified_closed == 0

    other = compliant_assessment.model_copy(deep=True)
    other.metadata.registry_version = "9.9.9"
    document = verify(vulnerable_assessment, other, generated_at=FIXED_TIME)
    assert document.blocked_reason_code == VerificationReasonCode.REGISTRY_BASELINE_CHANGED


def test_new_insufficient_evidence_cannot_close_a_finding(
    vulnerable_assessment, compliant_assessment
):
    other = compliant_assessment.model_copy(deep=True)
    _result(other, CLOSABLE_CONTROL).verdict = Verdict.INSUFFICIENT_EVIDENCE
    document = verify(vulnerable_assessment, other, generated_at=FIXED_TIME)
    item = next(i for i in document.items if i.control_id == CLOSABLE_CONTROL)
    assert item.outcome == VerificationOutcome.STILL_OPEN
    assert item.reason_code == VerificationReasonCode.REQUIRED_EVIDENCE_NOT_COLLECTED


def test_new_partial_cannot_close_a_finding(vulnerable_assessment, compliant_assessment):
    other = compliant_assessment.model_copy(deep=True)
    _result(other, CLOSABLE_CONTROL).verdict = Verdict.PARTIAL
    document = verify(vulnerable_assessment, other, generated_at=FIXED_TIME)
    item = next(i for i in document.items if i.control_id == CLOSABLE_CONTROL)
    assert item.outcome == VerificationOutcome.STILL_OPEN
    assert item.reason_code == VerificationReasonCode.NEW_VERDICT_NOT_PASS


def test_missing_new_evidence_cannot_close_a_finding(
    vulnerable_assessment, compliant_assessment
):
    other = compliant_assessment.model_copy(deep=True)
    _result(other, CLOSABLE_CONTROL).evidence_gaps = [
        EvidenceGap(evidence_key="tls_configuration", status="NOT_COLLECTED", required=True)
    ]
    document = verify(vulnerable_assessment, other, generated_at=FIXED_TIME)
    item = next(i for i in document.items if i.control_id == CLOSABLE_CONTROL)
    assert item.outcome == VerificationOutcome.STILL_OPEN
    assert item.reason_code == VerificationReasonCode.REQUIRED_EVIDENCE_NOT_COLLECTED


def test_unbacked_pass_cannot_close_a_finding(vulnerable_assessment, compliant_assessment):
    other = compliant_assessment.model_copy(deep=True)
    _result(other, CLOSABLE_CONTROL).evidence_ids = []
    document = verify(vulnerable_assessment, other, generated_at=FIXED_TIME)
    item = next(i for i in document.items if i.control_id == CLOSABLE_CONTROL)
    assert item.outcome == VerificationOutcome.STILL_OPEN


def test_control_absent_from_new_assessment_blocks_closure(
    vulnerable_assessment, compliant_assessment
):
    other = compliant_assessment.model_copy(deep=True)
    other.results = [r for r in other.results if r.control_id != CLOSABLE_CONTROL]
    document = verify(vulnerable_assessment, other, generated_at=FIXED_TIME)
    item = next(i for i in document.items if i.control_id == CLOSABLE_CONTROL)
    assert item.outcome == VerificationOutcome.VERIFICATION_BLOCKED
    assert item.reason_code == VerificationReasonCode.CONTROL_NOT_ASSESSED
    assert item.new_verdict is None


def test_verify_runs_writes_the_closure_artifact(runs):
    out_dir, document = verify_runs(
        previous_run_id="RUN-F4-VULNERABLE",
        new_run_id="RUN-F4-COMPLIANT",
        assessments_dir=runs["assessments"],
        clock=fixed_clock,
    )
    stored = json.loads((out_dir / "verification.json").read_text())
    assert stored == document.model_dump(mode="json")
    assert document.summary.verified_closed >= 1


def test_remediation_embeds_verification_when_asked(runs):
    _, remediation = remediate(
        run_id="RUN-F4-COMPLIANT",
        registry_path=APPROVED_PATH,
        evidence_dir=runs["evidence"],
        assessments_dir=runs["assessments"],
        previous_run_id="RUN-F4-VULNERABLE",
        clock=fixed_clock,
    )
    assert remediation.verification is not None
    assert remediation.verification.summary.verified_closed >= 1


# --- Final report -----------------------------------------------------------


@pytest.fixture(scope="module")
def report_html(vulnerable_assessment, vulnerable_remediation) -> str:
    return render_final_html(vulnerable_assessment, vulnerable_remediation)


def test_report_preserves_machine_verdicts(report_html, vulnerable_assessment):
    for result in vulnerable_assessment.results:
        assert result.control_id in report_html
    for verdict in {r.verdict.value for r in vulnerable_assessment.results}:
        assert verdict in report_html


def test_report_preserves_evidence_and_source_traceability(
    report_html, vulnerable_assessment
):
    failing = _first_failing(vulnerable_assessment)
    for evidence_id in failing.evidence_ids:
        assert evidence_id in report_html
    for source in failing.source_traceability.get("legal_sources") or []:
        assert source["document_id"] in report_html


def test_report_preserves_registry_metadata(report_html, vulnerable_remediation):
    assert vulnerable_remediation.metadata.registry_hash in report_html
    assert vulnerable_remediation.metadata.registry_version in report_html
    assert vulnerable_remediation.metadata.assessment_id in report_html


def test_report_shows_recommendations_and_verification_requirements(
    report_html, vulnerable_remediation
):
    item = next(
        i for i in vulnerable_remediation.items
        if i.action_type == ActionType.TECHNICAL_REMEDIATION
    )
    assert item.recommendation in report_html
    assert item.remediation_id in report_html
    for tool in item.verification.mcp_tools:
        assert tool in report_html


def test_mock_provider_shows_synthetic_disclaimer(report_html, vulnerable_assessment):
    assert vulnerable_assessment.metadata.provider == "mock"
    assert MOCK_BANNER in report_html


def test_report_is_self_contained(report_html):
    """No scripts and nothing the browser would have to fetch.

    Legal excerpts quote ELI URLs as text, so the check is for asset-loading
    markup rather than for the substring ``http``.
    """
    assert "<script" not in report_html
    assert "<link " not in report_html
    assert "<img" not in report_html
    assert " src=" not in report_html
    assert "@import" not in report_html
    assert "url(" not in report_html
    assert "<style>" in report_html


def test_report_is_well_formed_html(report_html):
    class Parser(HTMLParser):
        def error(self, message):  # pragma: no cover - defensive
            raise AssertionError(message)

    Parser().feed(report_html)
    assert report_html.startswith("<!DOCTYPE html>")


def test_report_is_reproducible_from_stored_artifacts(runs):
    out_dir = runs["assessments"] / "RUN-F4-VULNERABLE"
    remediate(
        run_id="RUN-F4-VULNERABLE",
        registry_path=APPROVED_PATH,
        evidence_dir=runs["evidence"],
        assessments_dir=runs["assessments"],
        clock=fixed_clock,
    )
    stored_html = (out_dir / "final-report.html").read_text()

    assessment = Assessment.model_validate(json.loads((out_dir / "assessment.json").read_text()))
    remediation = RemediationDocument.model_validate(
        json.loads((out_dir / "remediation.json").read_text())
    )
    assert assessment.summary.passed == json.loads(
        (out_dir / "assessment.json").read_text()
    )["summary"]["pass"]
    assert render_final_html(assessment, remediation, remediation.verification) == stored_html


def test_closure_status_is_rendered_when_available(runs, compliant_assessment):
    pre_remediation = build_remediation(
        remediation_preflight(
            registry_path=APPROVED_PATH,
            assessment_path=runs["assessments"] / "RUN-F4-COMPLIANT" / "assessment.json",
            evidence_path=runs["evidence"] / "RUN-F4-COMPLIANT" / "evidence.json",
        ),
        previous_assessment=_load_assessment(runs, "RUN-F4-VULNERABLE"),
        clock=fixed_clock,
    )
    html = render_final_html(compliant_assessment, pre_remediation, pre_remediation.verification)
    assert "Re-scan and closure status" in html
    assert VerificationOutcome.VERIFIED_CLOSED.value in html
