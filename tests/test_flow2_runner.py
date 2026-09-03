"""Flow 2 — registry validation, evidence execution and evidence integrity."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.config import PROJECT_ROOT, TO_BE_PROVIDED
from src.evidence.models import CollectionStatus, ReasonCode
from src.evidence.planner import build_plan, call_key_for, iter_evidence_requests
from src.evidence.runner import (
    RegistryIntegrityError,
    collect_evidence,
    load_approved_registry,
)
from src.evidence.targets import load_target_profile
from src.registry.versioning import latest_approved_path

APPROVED_PATH = latest_approved_path()
DRAFT_PATH = PROJECT_ROOT / "registry" / "controls.draft.json"
TARGET_PATH = PROJECT_ROOT / "targets" / "nextboss-demo.mock.json"

FIXED_TIME = "2026-08-20T12:00:00+00:00"


def fixed_clock() -> str:
    return FIXED_TIME


@pytest.fixture(scope="module")
def approved_registry() -> dict:
    assert APPROVED_PATH is not None, "an approved registry is required for Flow 2 tests"
    return json.loads(APPROVED_PATH.read_text())


@pytest.fixture(scope="module")
def target_profile():
    profile, _ = load_target_profile(TARGET_PATH)
    return profile


@pytest.fixture(scope="module")
def run_result(tmp_path_factory):
    out = tmp_path_factory.mktemp("evidence-baseline")
    run_dir, run = collect_evidence(
        registry_path=APPROVED_PATH,
        target_path=TARGET_PATH,
        output_dir=out,
        run_id="RUN-TEST-BASELINE",
        clock=fixed_clock,
    )
    return run_dir, run


def _write_registry(tmp_path: Path, data: dict, name: str = "controls.approved.v9.9.9.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data, indent=2))
    return path


# --- Registry / input validation ------------------------------------------


def test_rejects_draft_registry(tmp_path):
    with pytest.raises(RegistryIntegrityError, match="APPROVED"):
        collect_evidence(
            registry_path=DRAFT_PATH,
            target_path=TARGET_PATH,
            output_dir=tmp_path,
        )


def test_rejects_tampered_registry_hash(tmp_path, approved_registry):
    tampered = copy.deepcopy(approved_registry)
    tampered["controls"][0]["title"] = "Tampered title"
    registry_path = tmp_path / APPROVED_PATH.name
    registry_path.write_text(json.dumps(tampered, indent=2))

    manifest_src = APPROVED_PATH.with_name(APPROVED_PATH.stem + ".manifest.json")
    (tmp_path / manifest_src.name).write_text(manifest_src.read_text())

    with pytest.raises(RegistryIntegrityError, match="does not match its manifest"):
        load_approved_registry(registry_path)


def test_untampered_registry_matches_manifest():
    _, registry_hash = load_approved_registry(APPROVED_PATH)
    manifest = json.loads(
        APPROVED_PATH.with_name(APPROVED_PATH.stem + ".manifest.json").read_text()
    )
    assert registry_hash == manifest["approved_registry_hash"]


def test_records_registry_version_and_hash(run_result):
    _, run = run_result
    registry, registry_hash = load_approved_registry(APPROVED_PATH)
    assert run.run.registry_version == registry["metadata"]["registry_version"]
    assert run.run.registry_hash == registry_hash
    assert run.run.target_profile_hash
    assert run.run.provider == "mock"
    assert run.run.target_id == "nextboss-demo"


def test_rejects_unknown_mcp_tool(tmp_path, approved_registry, target_profile):
    mutated = copy.deepcopy(approved_registry)
    for control in mutated["controls"]:
        for item in control["evidence_plan"]:
            if item.get("mcp_tool") == "get_services":
                item["mcp_tool"] = "get_everything"

    plan = build_plan(mutated, target_profile)
    unknown = [s for s in plan.skipped if s.reason_code == "TOOL_NOT_REGISTERED"]
    assert unknown, "an unregistered tool must be refused"
    assert all(s.status == "TOOL_UNAVAILABLE" for s in unknown)
    assert all(call.tool != "get_everything" for call in plan.calls)


def test_unresolved_parameters_fail_closed(run_result):
    _, run = run_result
    unresolved = [
        item
        for item in run.evidence
        if item.status_reason_code == ReasonCode.PARAMETER_UNRESOLVED
    ]
    assert len(unresolved) == 8
    assert all(item.status == CollectionStatus.NOT_COLLECTED for item in unresolved)
    assert all(item.raw_artifact_ref is None for item in unresolved)
    assert all(item.normalized is None for item in unresolved)


def test_to_be_provided_is_never_converted_into_a_path(run_result, approved_registry):
    _, run = run_result
    unprovided = {
        (control["control_id"], item["evidence_key"])
        for control in approved_registry["controls"]
        for item in control["evidence_plan"]
        if TO_BE_PROVIDED in json.dumps(item.get("parameters", {}))
    }
    assert unprovided

    for item in run.evidence:
        links = {(r.control_id, r.evidence_key) for r in item.requested_by}
        if links & unprovided:
            assert item.status == CollectionStatus.NOT_COLLECTED
            assert item.status_reason_code == ReasonCode.PARAMETER_UNRESOLVED
            # No path was substituted for the placeholder.
            assert item.parameters_redacted.get("path") == TO_BE_PROVIDED

    collected_paths = {
        item.parameters_redacted.get("path")
        for item in run.evidence
        if item.status == CollectionStatus.COLLECTED
    }
    assert TO_BE_PROVIDED not in collected_paths


# --- Evidence execution ----------------------------------------------------


def test_parameter_resolution_uses_control_port_and_profile_host(run_result):
    _, run = run_result
    tls = [item for item in run.evidence if item.tool == "get_tls_configuration"]
    assert {item.parameters_redacted["port"] for item in tls} == {443, 8443}
    assert all(item.parameters_redacted["host"] == "nextboss-demo" for item in tls)


def test_only_approved_tools_are_invoked(run_result, approved_registry):
    _, run = run_result
    approved_tools = {
        item["mcp_tool"]
        for control in approved_registry["controls"]
        for item in control["evidence_plan"]
        if item.get("mcp_tool")
    }
    invoked = {
        item.tool for item in run.evidence if item.status == CollectionStatus.COLLECTED
    }
    assert invoked <= approved_tools


def test_safe_call_deduplication(approved_registry, target_profile):
    plan = build_plan(approved_registry, target_profile)
    requests_behind_calls = sum(len(call.requested_by) for call in plan.calls)
    assert requests_behind_calls == 48
    assert len(plan.calls) == 19
    assert len({call.call_key for call in plan.calls}) == 19


def test_deduplication_retains_every_requested_by_relationship(
    approved_registry, target_profile
):
    plan = build_plan(approved_registry, target_profile)
    collected_links = {
        (request.control_id, request.evidence_key)
        for call in plan.calls
        for request in call.requested_by
    }
    skipped_links = {
        (s.request.control_id, s.request.evidence_key) for s in plan.skipped
    }
    every_link = {
        (request.control_id, request.evidence_key)
        for request in iter_evidence_requests(approved_registry)
    }
    assert collected_links | skipped_links == every_link

    total_requests = sum(len(call.requested_by) for call in plan.calls) + len(plan.skipped)
    assert total_requests == 71


def test_materially_different_parameters_are_not_deduplicated(target_profile):
    scoped = call_key_for(
        target_id="t", provider="mock", tool="get_open_ports", parameters={"port": 8443}
    )
    unscoped = call_key_for(
        target_id="t", provider="mock", tool="get_open_ports", parameters={}
    )
    other_port = call_key_for(
        target_id="t", provider="mock", tool="get_open_ports", parameters={"port": 443}
    )
    assert len({scoped, unscoped, other_port}) == 3

    plan = build_plan(
        json.loads(APPROVED_PATH.read_text()),
        target_profile,
    )
    open_ports_params = [
        call.parameters for call in plan.calls if call.tool == "get_open_ports"
    ]
    assert {json.dumps(p, sort_keys=True) for p in open_ports_params} == {
        "{}",
        '{"port": 22}',
        '{"port": 443}',
        '{"port": 5432}',
        '{"port": 8443}',
    }


def test_documentary_evidence_is_not_sent_to_mcp(run_result):
    run_dir, run = run_result
    documentary = [
        item
        for item in run.evidence
        if item.status_reason_code == ReasonCode.DOCUMENTARY_OR_HUMAN
    ]
    assert len(documentary) == 15
    assert all(item.tool == "none" for item in documentary)
    assert all(item.raw_artifact_ref is None for item in documentary)
    assert all(item.call_id.startswith("NOCALL-") for item in documentary)


def test_every_approved_request_is_accounted_for(run_result):
    _, run = run_result
    accounted = sum(len(item.requested_by) for item in run.evidence)
    assert accounted == 71
    assert run.summary.evidence_requests_total == 71


# --- Evidence integrity ----------------------------------------------------


def test_sanitized_raw_evidence_is_retained_and_hashed(run_result):
    run_dir, run = run_result
    collected = [i for i in run.evidence if i.status == CollectionStatus.COLLECTED]
    assert len(collected) == 19

    for item in collected:
        artifact = run_dir / item.raw_artifact_ref
        assert artifact.exists()
        import hashlib

        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == item.raw_sha256


def test_raw_and_normalized_hashes_are_reproducible(tmp_path):
    hashes = []
    for index in range(2):
        _, run = collect_evidence(
            registry_path=APPROVED_PATH,
            target_path=TARGET_PATH,
            output_dir=tmp_path / f"run{index}",
            run_id="RUN-TEST-REPRO",
            clock=fixed_clock,
        )
        hashes.append(
            [(i.evidence_id, i.raw_sha256, i.normalized_sha256) for i in run.evidence]
        )
    assert hashes[0] == hashes[1]


def test_normalization_failure_retains_raw_artifact(tmp_path, monkeypatch):
    from src.evidence import normalize as normalize_module

    def explode(args, data, now):
        raise normalize_module.NormalizationError("synthetic normalization failure")

    monkeypatch.setitem(normalize_module.NORMALIZERS, "get_services", explode)

    run_dir, run = collect_evidence(
        registry_path=APPROVED_PATH,
        target_path=TARGET_PATH,
        output_dir=tmp_path,
        run_id="RUN-TEST-PARSE",
        clock=fixed_clock,
    )
    failed = [i for i in run.evidence if i.tool == "get_services"]
    assert len(failed) == 1
    item = failed[0]
    assert item.status == CollectionStatus.PARSE_ERROR
    assert item.status_reason_code == ReasonCode.NORMALIZATION_FAILED
    assert item.normalized is None
    assert item.normalized_sha256 is None
    assert (run_dir / item.raw_artifact_ref).exists()
    # The relationship to its eight requesting controls survives the failure.
    assert len(item.requested_by) == 8


def test_collection_status_is_always_explicit(run_result):
    _, run = run_result
    for item in run.evidence:
        assert item.status in set(CollectionStatus)
        if item.status != CollectionStatus.COLLECTED:
            assert item.status_reason_code is not None
            assert item.status_message


def test_collection_errors_are_machine_readable(run_result):
    _, run = run_result
    assert run.collection_errors
    for error in run.collection_errors:
        assert error.call_id
        assert error.requested_by
        assert error.status != CollectionStatus.COLLECTED
        assert error.reason_code in set(ReasonCode)
        assert error.message


def test_evidence_document_is_written_to_disk(run_result):
    run_dir, run = run_result
    document = json.loads((run_dir / "evidence.json").read_text())
    assert document["run"]["run_id"] == "RUN-TEST-BASELINE"
    assert len(document["evidence"]) == len(run.evidence)
    assert document["summary"]["mcp_calls_planned"] == 19
