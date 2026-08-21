"""Agent 1 — deterministic document & control intelligence orchestration."""

from __future__ import annotations

import json
from pathlib import Path

from datetime import datetime, timezone

from src.agents.coverage import (
    HOST_COMPONENT,
    assertion_refs_for_point,
    build_evidence_items_for_point,
    component_names_for_point,
    rules_for_point,
)
from src.agents.execution_model import write_execution_model
from src.config import PRODUCT_NAME, REGISTRY_DIR
from src.documents.crosswalk import EtsiClauseCrosswalk, cra_point_key, parse_etsi_crosswalk
from src.documents.injection_scan import scan_for_injection
from src.documents.loader import InventoryResult, assert_no_network, load_inventory
from src.documents.parser import ParsedDocument, parse_pdf
from src.documents.requirements import extract_category6_reference, extract_cra_requirements
from src.documents.source_classifier import ClassifiedDocument, classify_document
from src.documents.structure import StructureIndex, build_structure_index
from src.llm.provider import CachedAssistClient, NullProvider
from src.policy.assertions import SecurityAssertions, load_security_assertions
from src.product.profile import ProductProfile, load_product_profile
from src.registry.approval import compute_hash
from src.registry.models import (
    Applicability,
    ApplicabilityStatus,
    ComponentTarget,
    Confidence,
    ConflictEntry,
    Control,
    ControlsDraft,
    ControlsDraftMetadata,
    DocumentEntry,
    DocumentRegistry,
    DocumentRegistryMetadata,
    Evaluation,
    EvaluationMode,
    EvidenceMode,
    EvidencePlanItem,
    HumanReviewItem,
    LegalRequirement,
    ParameterStatus,
    RemediationSeed,
    RequirementEntry,
    SourceLocator,
    SourceReference,
    SourceTraceability,
    TargetContext,
    ToolStatus,
    UnresolvedItem,
)
from src.rules.dsl import validate_rules

# Evidence mapping: CRA point -> (evidence_key, mcp_tool, description)
# Retained as baseline for points that have technical evidence in the original POC.
TECHNICAL_EVIDENCE_MAP: dict[str, list[tuple[str, str, str]]] = {
    "I-2-b": [
        ("tls_configuration", "get_tls_configuration", "TLS protocol and cipher configuration for management interfaces"),
        ("open_ports", "get_open_ports", "Listening interfaces and ports exposed by default"),
    ],
    "I-2-d": [
        ("local_users", "get_users", "Local/privileged user accounts"),
        ("local_groups", "get_groups", "Group membership for privileged access"),
        ("management_services", "get_services", "Running management and authentication services"),
    ],
    "I-2-e": [
        ("tls_configuration", "get_tls_configuration", "TLS protocol/cipher configuration for data in transit"),
        ("certificates", "get_certificates", "Certificate configuration and validity"),
    ],
    "I-2-f": [
        ("file_permissions", "get_file_permissions", "Ownership and permissions on security-relevant configuration files"),
    ],
    "I-2-h": [
        ("services", "get_services", "Essential management services availability"),
        ("firewall_rules", "get_firewall_rules", "Firewall policy affecting service availability"),
    ],
    "I-2-j": [
        ("open_ports", "get_open_ports", "External interfaces and listening ports"),
        ("processes", "get_processes", "Running processes exposing attack surface"),
    ],
    "I-2-l": [
        ("security_logs", "get_security_logs", "Security-relevant log configuration"),
    ],
}

DOCUMENTARY_POINTS = {
    "I-1",
    "I-2-a",
    "I-2-c",
    "I-2-g",
    "I-2-i",
    "I-2-k",
    "I-2-m",
    "II-1",
    "II-2",
    "II-3",
    "II-4",
    "II-5",
    "II-6",
    "II-7",
    "II-8",
}

RULE_TEMPLATES: dict[str, list[dict]] = {
    "I-2-b": [
        {
            "all": [
                {"path": "tls_configuration.protocols.TLSv1_0", "operator": "EQ", "value": False},
                {"path": "tls_configuration.protocols.TLSv1_1", "operator": "EQ", "value": False},
            ]
        }
    ],
    "I-2-d": [
        {
            "all": [
                {"path": "local_users.default_accounts", "operator": "NOT_EXISTS", "value": None},
            ]
        }
    ],
    "I-2-j": [
        {
            "all": [
                {"path": "open_ports.unexpected_listeners", "operator": "EQ", "value": []},
            ]
        }
    ],
}

# Config path keys attached to components when building target_context
_COMPONENT_CONFIG_KEYS: dict[str, str] = {
    "SSH Administration": "ssh_config_file",
    "PostgreSQL": "postgres_config_file",
    "Management UI": "tls_config_file",
    "REST API": "tls_config_file",
}


def _point_key(req: RequirementEntry) -> str:
    part = req.cra_part or "I"
    point = req.cra_point or "1"
    clause = req.source_reference.source_locator.clause
    if part == "I" and point == "1":
        return "I-1"
    if part == "I" and point == "2" and clause:
        return f"I-2-{clause}"
    if part == "II":
        return f"II-{point}"
    return f"{part}-{point}"


def _determine_applicability(
    req: RequirementEntry,
    crosswalk: list[EtsiClauseCrosswalk],
) -> Applicability:
    key = _point_key(req)
    conditions: list[str] = []
    for cw in crosswalk:
        if cra_point_key(cw.cra_part, cw.cra_point) == key or (
            key.startswith("I-2-") and cw.cra_point == key.split("-")[-1]
        ):
            for r in cw.requirements:
                conditions.extend(r.applicability_conditions)

    if conditions:
        return Applicability(
            status=ApplicabilityStatus.CONDITIONAL,
            reason=(
                "ETSI defines applicability conditions requiring product architecture facts "
                "not present in the declared product profile"
            ),
            assumptions=[f"Unresolved condition: {c}" for c in conditions[:3]],
        )

    if key in DOCUMENTARY_POINTS:
        return Applicability(
            status=ApplicabilityStatus.APPLICABLE,
            reason="Binding CRA requirement; evidence is documentary or process-based",
            assumptions=[],
        )

    return Applicability(
        status=ApplicabilityStatus.APPLICABLE,
        reason="Binding CRA requirement applicable to Class I Category 6 NMS",
        assumptions=["Product core functionality is network management per binding classification"],
    )


def _build_target_context(key: str, profile: ProductProfile) -> TargetContext | None:
    names = component_names_for_point(key)
    if not names:
        return None

    components: list[ComponentTarget] = []
    for name in names:
        if name == HOST_COMPONENT:
            components.append(ComponentTarget(component=HOST_COMPONENT))
            continue
        iface = profile.interface_by_name(name)
        if iface is None:
            continue
        config_path = None
        path_key = _COMPONENT_CONFIG_KEYS.get(name)
        if path_key:
            config_path = getattr(profile.configuration, path_key)
        components.append(
            ComponentTarget(
                component=iface.name,
                interface_type=iface.type,
                protocol=iface.protocol,
                port=iface.port,
                config_path=config_path,
            )
        )

    if not components:
        return None

    return TargetContext(
        components=components,
        platform=profile.platform.operating_system,
    )


def _merge_evidence_items(
    key: str,
    profile: ProductProfile,
    *,
    include_documentary: bool,
) -> tuple[list[EvidencePlanItem], list[UnresolvedItem]]:
    """Build evidence plan from coverage matrix (+ optional documentary seed)."""
    items: list[EvidencePlanItem] = []
    unresolved: list[UnresolvedItem] = []
    seen: set[str] = set()

    if include_documentary:
        items.append(
            EvidencePlanItem(
                evidence_key="process_documentation",
                description="Manufacturer process documentation, policy records, or technical documentation",
                mode=EvidenceMode.DOCUMENTARY_OR_HUMAN,
                mcp_tool=None,
                tool_status=ToolStatus.REQUIRED_NEW_TOOL,
                required=True,
            )
        )
        seen.add("process_documentation")

    # Coverage-matrix technical evidence (product-specific parameters)
    for built in build_evidence_items_for_point(key, profile):
        if built.evidence_key in seen:
            continue
        seen.add(built.evidence_key)
        status = (
            ParameterStatus.TO_BE_PROVIDED
            if built.parameter_status == "TO_BE_PROVIDED"
            else ParameterStatus.RESOLVED
        )
        items.append(
            EvidencePlanItem(
                evidence_key=built.evidence_key,
                description=built.description,
                mode=EvidenceMode.TECHNICAL,
                mcp_tool=built.mcp_tool,
                tool_status=ToolStatus.AVAILABLE,
                parameters=built.parameters,
                parameter_status=status,
                required=True,
            )
        )
        if built.unresolved_reason:
            unresolved.append(
                UnresolvedItem(
                    item_id=f"PATH-{built.evidence_key}",
                    description=built.unresolved_reason,
                )
            )

    # Preserve original TECHNICAL_EVIDENCE_MAP keys not already covered
    for ev_key, mcp_tool, desc in TECHNICAL_EVIDENCE_MAP.get(key, []):
        if ev_key in seen:
            continue
        # Skip if a port-suffixed variant already covers this family
        if any(s.startswith(f"{ev_key}_") for s in seen):
            continue
        seen.add(ev_key)
        items.append(
            EvidencePlanItem(
                evidence_key=ev_key,
                description=desc,
                mode=EvidenceMode.TECHNICAL,
                mcp_tool=mcp_tool,
                tool_status=ToolStatus.AVAILABLE,
                parameters={},
                parameter_status=ParameterStatus.RESOLVED,
                required=True,
            )
        )

    if not items:
        items.append(
            EvidencePlanItem(
                evidence_key="technical_documentation",
                description="Technical documentation or human review required",
                mode=EvidenceMode.DOCUMENTARY_OR_HUMAN,
                mcp_tool=None,
                tool_status=ToolStatus.REQUIRED_NEW_TOOL,
                required=True,
            )
        )

    return items, unresolved


def _build_evidence_plan(
    key: str,
    profile: ProductProfile,
) -> tuple[list[EvidencePlanItem], list[UnresolvedItem]]:
    if key in DOCUMENTARY_POINTS:
        return _merge_evidence_items(key, profile, include_documentary=True)
    return _merge_evidence_items(key, profile, include_documentary=False)


def _merge_rules(key: str, policy: SecurityAssertions) -> list[dict]:
    """Merge RULE_TEMPLATES with YAML-derived rules; validate before return."""
    merged: list[dict] = []
    seen: set[str] = set()
    for rule in RULE_TEMPLATES.get(key, []) + rules_for_point(key, policy):
        marker = repr(rule)
        if marker not in seen:
            seen.add(marker)
            merged.append(rule)
    if merged:
        validate_rules(merged)
    return merged


def _build_evaluation(key: str, evidence: list[EvidencePlanItem], policy: SecurityAssertions) -> Evaluation:
    # Preserve Flow 1 semantics: any documentary evidence forces human/agent reasoning.
    if any(e.mode == EvidenceMode.DOCUMENTARY_OR_HUMAN for e in evidence):
        return Evaluation(mode=EvaluationMode.HUMAN_OR_AGENT_REASONING, rules=[])
    rules = _merge_rules(key, policy)
    if rules:
        return Evaluation(mode=EvaluationMode.DETERMINISTIC, rules=rules)
    return Evaluation(mode=EvaluationMode.HUMAN_OR_AGENT_REASONING, rules=[])


def _etsi_refs_for_point(key: str, crosswalk: list[EtsiClauseCrosswalk]) -> list[SourceReference]:
    refs: list[SourceReference] = []
    for cw in crosswalk:
        cw_key = cra_point_key(cw.cra_part, cw.cra_point)
        if cw_key == key or (key.startswith("I-2-") and cw.cra_point.endswith(key.split("-")[-1])):
            for r in cw.requirements[:2]:
                refs.append(
                    SourceReference(
                        document_id="ETSI-EN-304-621",
                        source_locator=SourceLocator(
                            page=r.pdf_page,
                            clause=r.requirement_id,
                            section=cw.clause_number,
                        ),
                        source_excerpt=r.text[:300],
                        normalized_summary=f"ETSI {r.requirement_id} technical reference for CRA {key}",
                        binding_status="NON_BINDING",
                    )
                )
    return refs


def _derive_control(
    idx: int,
    req: RequirementEntry,
    crosswalk: list[EtsiClauseCrosswalk],
    category6: SourceReference | None,
    assist: CachedAssistClient,
    profile: ProductProfile,
    policy: SecurityAssertions,
) -> tuple[Control, list[UnresolvedItem]]:
    key = _point_key(req)
    applicability = _determine_applicability(req, crosswalk)
    evidence, unresolved = _build_evidence_plan(key, profile)
    evaluation = _build_evaluation(key, evidence, policy)
    etsi_refs = _etsi_refs_for_point(key, crosswalk)
    etsi_ids = [r.source_locator.clause for r in etsi_refs if r.source_locator.clause]
    target_context = _build_target_context(key, profile)
    assertion_refs = assertion_refs_for_point(key)

    control_id = f"NMS-CRA-{idx:04d}"
    nms_interpretation = (
        f"For NextBoss-XT (Class I Category 6 NMS), CRA Annex I Part {req.cra_part} "
        f"point ({req.cra_point}) requires observable security properties on the "
        f"management plane and/or documented manufacturer processes."
    )
    technical_control = (
        f"Verify {key} compliance through "
        f"{'host infrastructure evidence' if evidence[0].mode == EvidenceMode.TECHNICAL else 'documentary/process evidence'}."
    )

    proposal = assist.get_or_propose(
        control_id=control_id,
        requirement_text=req.legal_requirement_text,
        etsi_requirement_id=etsi_ids[0] if etsi_ids else key,
        product_context=f"{PRODUCT_NAME} Class I Category 6 NMS",
    )
    if proposal:
        nms_interpretation = proposal.nms_interpretation
        technical_control = proposal.technical_control

    has_unresolved_paths = any(
        e.parameter_status == ParameterStatus.TO_BE_PROVIDED for e in evidence
    )
    # Never invent paths; flag for human review when profile has TO_BE_PROVIDED
    for item in unresolved:
        item.item_id = f"{control_id}-{item.item_id}"

    classification_sources = [category6] if category6 else []
    control = Control(
        control_id=control_id,
        title=f"CRA {key}: {req.normalized_requirement[:80]}",
        source_traceability=SourceTraceability(
            legal_sources=[req.source_reference],
            classification_sources=classification_sources,
            guidance_sources=[],
            technical_reference_sources=etsi_refs,
        ),
        applicability=applicability,
        legal_requirement=LegalRequirement(
            original_text=req.legal_requirement_text,
            normalized_requirement=req.normalized_requirement,
        ),
        nms_interpretation=nms_interpretation,
        technical_control=technical_control,
        target_context=target_context,
        evidence_plan=evidence,
        assertion_refs=assertion_refs,
        evaluation=evaluation,
        remediation_seed=RemediationSeed(
            recommendation=(
                f"Review and align NextBoss-XT configuration/processes with CRA {key}. "
                "Apply advisory fixes outside this POC."
            ),
            verification_evidence_keys=[e.evidence_key for e in evidence],
        ),
        human_review_required=(
            applicability.status in {
                ApplicabilityStatus.CONDITIONAL,
                ApplicabilityStatus.HUMAN_REVIEW_REQUIRED,
            }
            or evaluation.mode == EvaluationMode.HUMAN_OR_AGENT_REASONING
            or has_unresolved_paths
        ),
        confidence=Confidence.HIGH if etsi_refs else Confidence.MEDIUM,
        etsi_requirement_ids=etsi_ids,
    )
    return control, unresolved


def _generated_at_from_inventory(inventory: InventoryResult) -> str:
    """Deterministic timestamp derived from source file mtimes."""
    mtimes = [
        item.mtime
        for item in inventory.authoritative + inventory.supporting
        if item.present and item.mtime
    ]
    return max(mtimes) if mtimes else datetime.now(timezone.utc).isoformat()


def run_agent1(
    *,
    assist_client: CachedAssistClient | None = None,
    registry_dir: Path = REGISTRY_DIR,
) -> tuple[DocumentRegistry, ControlsDraft]:
    assert_no_network()
    assist = assist_client or CachedAssistClient(provider=NullProvider())

    profile, profile_sha = load_product_profile()
    policy, policy_sha = load_security_assertions()

    inventory = load_inventory()
    parsed: dict[str, ParsedDocument] = {}
    classified: dict[str, ClassifiedDocument] = {}
    indices: dict[str, StructureIndex] = {}

    all_items = inventory.authoritative + inventory.supporting
    for item in all_items:
        if item.present and item.path:
            doc = parse_pdf(item.path, item.document_id)
            parsed[item.document_id] = doc
            classified[item.document_id] = classify_document(item, doc)
            indices[item.document_id] = build_structure_index(doc)

    # Build document registry
    doc_entries = [
        DocumentEntry(
            document_id=c.document_id,
            filename=c.filename,
            title=c.title,
            issuer=c.issuer,
            source_type=c.source_type,
            binding_status=c.binding_status,
            document_status=c.document_status,
            authority_level=c.authority_level,
            version_date=c.version_date,
            sha256=c.sha256,
            page_count=c.page_count,
            present=c.present,
            tier=next(
                (i.tier for i in all_items if i.document_id == c.document_id),
                "supporting",
            ),
        )
        for c in classified.values()
    ]

    requirements: list[RequirementEntry] = []
    cra_doc = parsed.get("CRA-2024-2847")
    if cra_doc:
        requirements = extract_cra_requirements(cra_doc)

    category6 = None
    oj_doc = parsed.get("CRA-2025-2392")
    if oj_doc:
        category6 = extract_category6_reference(oj_doc)

    crosswalk: list[EtsiClauseCrosswalk] = []
    etsi_doc = parsed.get("ETSI-EN-304-621")
    if etsi_doc:
        crosswalk = parse_etsi_crosswalk(etsi_doc)

    conflicts: list[ConflictEntry] = []
    human_review: list[HumanReviewItem] = []
    unresolved: list[UnresolvedItem] = []
    injection_candidates: list[dict] = []

    for c in classified.values():
        for conflict in c.metadata_conflicts:
            conflicts.append(
                ConflictEntry(
                    conflict_id=conflict["conflict_id"],
                    description=conflict["description"],
                    sources=[c.document_id],
                    precedence_applied="Record both metadata values; body version is primary",
                    human_review_required=True,
                    details=conflict,
                )
            )
            human_review.append(
                HumanReviewItem(
                    item_id=conflict["conflict_id"],
                    reason=conflict["description"],
                )
            )

    for item in inventory.absent:
        unresolved.append(
            UnresolvedItem(
                item_id=f"ABSENT-{item.document_id}",
                description=f"Expected supporting document absent: {item.filename}",
                source_document_id=item.document_id,
            )
        )

    for doc in parsed.values():
        for candidate in scan_for_injection(doc.full_cleaned_text[:5000]):
            injection_candidates.append(
                {
                    "document_id": doc.document_id,
                    "pattern": candidate.pattern,
                    "matched_text": candidate.matched_text,
                }
            )

    guidance_refs: list[SourceReference] = []
    technical_refs: list[SourceReference] = []
    std_refs: list[SourceReference] = []

    for cw in crosswalk:
        for r in cw.requirements[:1]:
            technical_refs.append(
                SourceReference(
                    document_id="ETSI-EN-304-621",
                    source_locator=SourceLocator(
                        page=r.pdf_page,
                        clause=r.requirement_id,
                        section=cw.clause_number,
                    ),
                    source_excerpt=r.text[:200],
                    normalized_summary=f"ETSI crosswalk clause {cw.clause_number} -> CRA Annex I Part {cw.cra_part} ({cw.cra_point})",
                    binding_status="NON_BINDING",
                )
            )

    generated_at = _generated_at_from_inventory(inventory)

    controls: list[Control] = []
    for i, req in enumerate(requirements):
        control, path_unresolved = _derive_control(
            i + 1, req, crosswalk, category6, assist, profile, policy
        )
        controls.append(control)
        unresolved.extend(path_unresolved)

    # Stable order for unresolved path items
    unresolved.sort(key=lambda u: u.item_id)

    doc_registry = DocumentRegistry(
        metadata=DocumentRegistryMetadata(generated_at=generated_at),
        documents=doc_entries,
        requirements=requirements,
        classification_references=[category6] if category6 else [],
        guidance_references=guidance_refs,
        technical_references=technical_refs,
        standardisation_references=std_refs,
        conflicts=conflicts,
        human_review_items=human_review,
        unresolved_items=unresolved,
        injection_candidates=injection_candidates,
    )

    controls_draft = ControlsDraft(
        metadata=ControlsDraftMetadata(
            generated_at=generated_at,
            product_profile_sha256=profile_sha,
            security_assertions_sha256=policy_sha,
        ),
        controls=controls,
    )

    registry_dir.mkdir(parents=True, exist_ok=True)
    doc_path = registry_dir / "document_registry.json"
    ctrl_path = registry_dir / "controls.draft.json"
    doc_path.write_text(doc_registry.model_dump_json(indent=2))
    ctrl_path.write_text(controls_draft.model_dump_json(indent=2))

    write_execution_model()

    return doc_registry, controls_draft


def registry_hashes(registry_dir: Path = REGISTRY_DIR) -> dict[str, str]:
    doc_path = registry_dir / "document_registry.json"
    ctrl_path = registry_dir / "controls.draft.json"
    result = {}
    if doc_path.exists():
        result["document_registry"] = compute_hash(json.loads(doc_path.read_text()))
    if ctrl_path.exists():
        result["controls_draft"] = compute_hash(json.loads(ctrl_path.read_text()))
    return result
