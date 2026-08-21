"""Flow 1 test suite."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from src.agents.agent1 import registry_hashes, run_agent1
from src.config import REGISTRY_DIR, SUPPORTING_DIR
from src.documents.citations import validate_excerpt, validate_locator
from src.documents.loader import InventoryResult, load_inventory
from src.documents.parser import ParsedDocument, PageText, parse_pdf
from src.documents.source_classifier import classify_document
from src.documents.structure import StructureIndex, build_structure_index
from src.llm.provider import CachedAssistClient, NullProvider
from src.registry.approval import (
    approve_registry,
    load_controls_draft,
    refuse_draft_as_approved,
)
from src.registry.models import (
    ControlsDraft,
    ControlsDraftMetadata,
    Control,
    DocumentRegistry,
    EvidenceMode,
    Evaluation,
    EvaluationMode,
    LegalRequirement,
    RemediationSeed,
    SourceLocator,
    SourceReference,
    SourceTraceability,
    Applicability,
    ApplicabilityStatus,
)
from src.registry.validator import validate_controls_draft, validate_document_registry
from src.rules.dsl import validate_rule, validate_rules


@pytest.fixture(scope="module")
def ingested():
    doc_registry, controls = run_agent1()
    return doc_registry, controls


def test_source_authority_classification():
    inventory = load_inventory()
    for item in inventory.authoritative + inventory.supporting:
        if not item.present:
            continue
        doc = parse_pdf(item.path, item.document_id)
        classified = classify_document(item, doc)
        if item.document_id == "CRA-2024-2847":
            assert classified.authority_level == 1
            assert classified.binding_status == "BINDING"
        elif item.document_id == "CRA-2025-2392":
            assert classified.authority_level == 1
        elif item.document_id == "C-2026-5252":
            assert classified.authority_level == 2
            assert classified.binding_status == "NON_BINDING"
        elif item.document_id == "ETSI-EN-304-621":
            assert classified.authority_level == 3
            assert classified.document_status == "ON_APPROVAL"
        elif item.document_id == "C-2025-618":
            assert classified.authority_level == 4


def test_absent_supporting_document(tmp_path: Path):
    auth = tmp_path / "authoritative"
    sup = tmp_path / "supporting"
    auth.mkdir()
    sup.mkdir()
    shutil.copytree(
        Path(__file__).resolve().parent.parent / "documents" / "authoritative",
        auth,
        dirs_exist_ok=True,
    )
    # Only copy one supporting doc
    src = Path(__file__).resolve().parent.parent / "documents" / "supporting"
    shutil.copy(src / "ETSI_EN_304_621_V1.0.5.pdf", sup / "ETSI_EN_304_621_V1.0.5.pdf")

    inventory = load_inventory(authoritative_dir=auth, supporting_dir=sup)
    absent = [a for a in inventory.absent if a.tier == "supporting"]
    assert len(absent) == 2
    assert any(a.filename == "C_2026_5252_CRA_Guidance.pdf" for a in absent)


def test_fabricated_citation_prevention():
    inventory = load_inventory()
    item = next(i for i in inventory.authoritative if i.document_id == "CRA-2024-2847")
    doc = parse_pdf(item.path, item.document_id)
    result = validate_excerpt(
        "This text was never in the regulation and is completely fabricated.",
        doc,
        pdf_page=1,
    )
    assert not result.valid
    assert any("not found" in e for e in result.errors)


def test_conflicting_source_precedence(ingested):
    doc_registry, _ = ingested
    etsi_conflicts = [c for c in doc_registry.conflicts if "ETSI" in c.conflict_id]
    assert len(etsi_conflicts) >= 1
    conflict = etsi_conflicts[0]
    assert conflict.human_review_required
    assert "body version" in conflict.precedence_applied.lower() or conflict.details


def test_null_page_reference():
    index = StructureIndex(document_id="TEST")
    result = validate_locator(index, page=None, article=None)
    assert result.valid
    assert any("null" in w.lower() for w in result.warnings)


def test_legal_vs_technical_reference_separation(ingested):
    doc_registry, controls = ingested
    for req in doc_registry.requirements:
        assert req.source_reference.binding_status == "BINDING"
    for ref in doc_registry.technical_references:
        assert ref.binding_status == "NON_BINDING"
    for control in controls.controls:
        for ts in control.source_traceability.technical_reference_sources:
            assert ts.binding_status == "NON_BINDING"


def test_category6_traceability(ingested):
    doc_registry, controls = ingested
    assert len(doc_registry.classification_references) >= 1
    cat6 = doc_registry.classification_references[0]
    assert cat6.document_id == "CRA-2025-2392"
    assert "Network" in cat6.source_excerpt or "management" in cat6.source_excerpt
    assert any(
        control.source_traceability.classification_sources
        for control in controls.controls
    )


def test_required_new_tool(ingested):
    _, controls = ingested
    doc_controls = [
        c
        for c in controls.controls
        if any(
            e.tool_status.value == "REQUIRED_NEW_TOOL"
            for e in c.evidence_plan
        )
    ]
    assert len(doc_controls) >= 1


def test_documentary_manual_evidence(ingested):
    _, controls = ingested
    doc_evidence = [
        c
        for c in controls.controls
        if any(e.mode == EvidenceMode.DOCUMENTARY_OR_HUMAN for e in c.evidence_plan)
    ]
    assert len(doc_evidence) >= 5
    for c in doc_evidence:
        assert c.evaluation.mode == EvaluationMode.HUMAN_OR_AGENT_REASONING


def test_rule_dsl_schema_validation():
    rule = {
        "all": [
            {"path": "tls_configuration.protocols.TLSv1_0", "operator": "EQ", "value": False},
            {"path": "tls_configuration.protocols.TLSv1_1", "operator": "NOT_EXISTS"},
        ]
    }
    validated = validate_rule(rule)
    assert validated is not None
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        validate_rule({"path": "x", "operator": "EQ"})


def test_draft_cannot_be_approved_input(tmp_path: Path):
    draft = ControlsDraft(
        metadata=ControlsDraftMetadata(status="DRAFT"),
        controls=[],
    )
    path = tmp_path / "controls.draft.json"
    path.write_text(draft.model_dump_json())
    with pytest.raises(ValueError, match="DRAFT"):
        refuse_draft_as_approved(path)


def test_reproducible_registry_no_provider():
    run_agent1()
    hash1 = registry_hashes()
    run_agent1()
    hash2 = registry_hashes()
    assert hash1["document_registry"] == hash2["document_registry"]
    assert hash1["controls_draft"] == hash2["controls_draft"]


def test_stale_assist_cache_does_not_change_hash(tmp_path: Path):
    proposals = tmp_path / "proposals"
    proposals.mkdir()
    stale = proposals / "NMS-CRA-0001.json"
    stale.write_text(
        json.dumps(
            {
                "control_id": "NMS-CRA-0001",
                "technical_control": "STALE DIFFERENT TEXT",
                "nms_interpretation": "stale",
                "model_name": "StaleModel",
                "prompt_hash": "deadbeef",
                "temperature": 0.9,
            }
        )
    )
    assist = CachedAssistClient(provider=NullProvider(), proposals_dir=proposals)
    run_agent1(assist_client=assist)
    hashes_with_stale = registry_hashes()
    run_agent1(assist_client=assist)
    hashes_second = registry_hashes()
    assert hashes_with_stale == hashes_second


def test_approval_workflow(tmp_path: Path, ingested):
    _, controls = ingested
    from src.registry import approval

    original_approved = approval.APPROVED_DIR
    approval.APPROVED_DIR = tmp_path / "approved"
    try:
        with pytest.raises(ValueError, match="blocking conflict"):
            approve_registry(
                controls,
                approver="Test User",
                version="0.0.1",
                blocking_conflicts=[{"id": "test"}],
            )
        out, manifest = approve_registry(
            controls,
            approver="Test User",
            version="0.0.1",
            blocking_conflicts=None,
        )
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["metadata"]["status"] == "APPROVED"
        assert manifest.approved_registry_hash
    finally:
        approval.APPROVED_DIR = original_approved
