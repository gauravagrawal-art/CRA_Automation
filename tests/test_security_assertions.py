"""Broader security assertions enhancement tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.agents.agent1 import registry_hashes, run_agent1
from src.agents.coverage import AREA_MATRIX
from src.config import TO_BE_PROVIDED
from src.policy.assertions import load_security_assertions, resolve_assertion_ref
from src.product.profile import is_resolved, load_product_profile
from src.registry.models import (
    Applicability,
    ApplicabilityStatus,
    Control,
    ControlsDraft,
    ControlsDraftMetadata,
    Evaluation,
    EvaluationMode,
    EvidenceMode,
    EvidencePlanItem,
    LegalRequirement,
    ParameterStatus,
    RemediationSeed,
    SourceLocator,
    SourceReference,
    SourceTraceability,
    ToolStatus,
)
from src.registry.validator import validate_controls_draft


@pytest.fixture(scope="module")
def profile_and_policy():
    profile, profile_sha = load_product_profile()
    policy, policy_sha = load_security_assertions()
    return profile, profile_sha, policy, policy_sha


@pytest.fixture(scope="module")
def ingested():
    doc_registry, controls = run_agent1()
    return doc_registry, controls


def test_product_profile_loads_and_preserves_to_be_provided(profile_and_policy):
    profile, profile_sha, _, _ = profile_and_policy
    assert profile.product.name == "NextBoss-XT"
    assert profile.platform.operating_system == "RHEL"
    assert {i.port for i in profile.interfaces} == {22, 443, 8443, 5432}
    assert profile.configuration.tls_config_file == TO_BE_PROVIDED
    assert profile.configuration.application_config == TO_BE_PROVIDED
    assert profile.configuration.postgres_config_file == TO_BE_PROVIDED
    assert profile.configuration.ssh_config_file == "/etc/ssh/sshd_config"
    assert not is_resolved(profile.configuration.tls_config_file)
    assert is_resolved(profile.configuration.ssh_config_file)
    assert len(profile_sha) == 64


def test_security_assertions_load_and_resolve_refs(profile_and_policy):
    _, _, policy, policy_sha = profile_and_policy
    assert policy.metadata.source_type == "INTERNAL_TECHNICAL_BASELINE"
    assert resolve_assertion_ref(policy, "tls.disallowed_protocols") == [
        "TLSv1.0",
        "TLSv1.1",
    ]
    assert resolve_assertion_ref(policy, "tls.certificate.must_not_be_expired") is True
    named = resolve_assertion_ref(policy, "ssh.SSH-ROOT-LOGIN")
    assert named.id == "SSH-ROOT-LOGIN"
    assert named.key == "PermitRootLogin"
    assert resolve_assertion_ref(policy, "postgresql.POSTGRES-NOT-PUBLIC").id == (
        "POSTGRES-NOT-PUBLIC"
    )
    with pytest.raises(KeyError):
        resolve_assertion_ref(policy, "tls.does_not_exist")
    assert len(policy_sha) == 64


def test_control_count_and_ids_stable(ingested):
    _, controls = ingested
    assert len(controls.controls) == 22
    ids = [c.control_id for c in controls.controls]
    assert ids == [f"NMS-CRA-{i:04d}" for i in range(1, 23)]


def test_all_assertion_refs_resolve(ingested, profile_and_policy):
    _, controls = ingested
    _, _, policy, _ = profile_and_policy
    for control in controls.controls:
        for ref in control.assertion_refs:
            resolve_assertion_ref(policy, ref)


def test_all_ports_declared_in_profile(ingested, profile_and_policy):
    _, controls = ingested
    profile, _, _, _ = profile_and_policy
    declared = profile.declared_ports()
    for control in controls.controls:
        for ev in control.evidence_plan:
            port = ev.parameters.get("port")
            if port is not None:
                assert int(port) in declared
        if control.target_context:
            for comp in control.target_context.components:
                if comp.port is not None:
                    assert comp.port in declared


def test_eleven_areas_represented(ingested):
    _, controls = ingested
    titles = " ".join(c.title for c in controls.controls)
    covered_areas = set()
    for area in AREA_MATRIX:
        for control in controls.controls:
            point = control.title[4:].split(":", 1)[0].strip()
            if point in area.cra_points and any(
                r in control.assertion_refs for r in area.assertion_refs
            ):
                covered_areas.add(area.area_id)
                break
    assert covered_areas == {a.area_id for a in AREA_MATRIX}, covered_areas
    assert "CRA II-1" in titles or any("II-1" in c.title for c in controls.controls)


def test_to_be_provided_not_invented(ingested):
    doc_registry, controls = ingested
    path_unresolved = [
        u for u in doc_registry.unresolved_items if "TO_BE_PROVIDED" in u.description
    ]
    assert len(path_unresolved) >= 1
    for control in controls.controls:
        for ev in control.evidence_plan:
            if ev.parameters.get("path") == TO_BE_PROVIDED:
                assert ev.parameter_status == ParameterStatus.TO_BE_PROVIDED
                assert control.human_review_required


def test_no_pass_fail_in_controls(ingested):
    _, controls = ingested
    for control in controls.controls:
        dumped = json.dumps(control.model_dump())
        assert '"PASS"' not in dumped
        assert '"FAIL"' not in dumped
        assert "pass" not in control.model_dump()
        assert "fail" not in control.model_dump()
        assert "verdict" not in control.model_dump()


def test_metadata_hashes_present(ingested):
    _, controls = ingested
    assert controls.metadata.schema_version == "1.1"
    assert controls.metadata.product_profile_sha256
    assert controls.metadata.security_assertions_sha256
    assert len(controls.metadata.product_profile_sha256) == 64


def test_validator_rejects_unknown_assertion_ref(ingested, profile_and_policy):
    _, controls = ingested
    profile, _, policy, _ = profile_and_policy
    bad = copy.deepcopy(controls)
    bad.controls[0].assertion_refs = ["tls.not_a_real_ref"]
    result = validate_controls_draft(bad, profile=profile, policy=policy)
    assert not result.valid
    assert any("unresolvable assertion_ref" in e for e in result.errors)


def test_validator_rejects_undeclared_port(ingested, profile_and_policy):
    _, controls = ingested
    profile, _, policy, _ = profile_and_policy
    bad = copy.deepcopy(controls)
    # Find a technical evidence item or create one
    target = bad.controls[0]
    target.evidence_plan.append(
        EvidencePlanItem(
            evidence_key="bogus_port",
            description="bogus",
            mode=EvidenceMode.TECHNICAL,
            mcp_tool="get_open_ports",
            tool_status=ToolStatus.AVAILABLE,
            parameters={"port": 9999},
            required=True,
        )
    )
    result = validate_controls_draft(bad, profile=profile, policy=policy)
    assert not result.valid
    assert any("undeclared port 9999" in e for e in result.errors)


def test_backward_compat_absent_target_context(profile_and_policy):
    """Draft without target_context/assertion_refs still validates schema-wise."""
    profile, _, policy, _ = profile_and_policy
    control = Control(
        control_id="NMS-CRA-9999",
        title="CRA I-1: test",
        source_traceability=SourceTraceability(
            legal_sources=[
                SourceReference(
                    document_id="CRA-2024-2847",
                    source_locator=SourceLocator(page=1),
                    source_excerpt="placeholder",
                    binding_status="BINDING",
                )
            ]
        ),
        applicability=Applicability(
            status=ApplicabilityStatus.APPLICABLE,
            reason="test",
        ),
        legal_requirement=LegalRequirement(
            original_text="placeholder",
            normalized_requirement="test",
        ),
        nms_interpretation="test",
        technical_control="test",
        target_context=None,
        evidence_plan=[
            EvidencePlanItem(
                evidence_key="process_documentation",
                description="docs",
                mode=EvidenceMode.DOCUMENTARY_OR_HUMAN,
                mcp_tool=None,
                tool_status=ToolStatus.REQUIRED_NEW_TOOL,
            )
        ],
        assertion_refs=[],
        evaluation=Evaluation(mode=EvaluationMode.HUMAN_OR_AGENT_REASONING, rules=[]),
        remediation_seed=RemediationSeed(recommendation="n/a"),
    )
    draft = ControlsDraft(
        metadata=ControlsDraftMetadata(status="DRAFT"),
        controls=[control],
    )
    # Without PDF citation checks — schema + profile/policy guards only
    result = validate_controls_draft(draft, profile=profile, policy=policy)
    # Missing legal citation PDFs not supplied; may warn/error on citation if parsed
    # With no parsed_docs, citation checks are skipped — should be valid
    assert result.valid, result.errors


def test_documentary_controls_remain_human_reasoning(ingested):
    _, controls = ingested
    doc_evidence = [
        c
        for c in controls.controls
        if any(e.mode == EvidenceMode.DOCUMENTARY_OR_HUMAN for e in c.evidence_plan)
    ]
    assert len(doc_evidence) >= 5
    for c in doc_evidence:
        assert c.evaluation.mode == EvaluationMode.HUMAN_OR_AGENT_REASONING


def test_reproducible_with_profile_policy():
    run_agent1()
    hash1 = registry_hashes()
    run_agent1()
    hash2 = registry_hashes()
    assert hash1 == hash2
