"""Registry validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.agents.coverage import HOST_COMPONENT
from src.config import MCP_CAPABILITY_CATALOG, TO_BE_PROVIDED
from src.documents.citations import validate_citation
from src.documents.crosswalk import parse_etsi_crosswalk
from src.documents.parser import ParsedDocument
from src.documents.structure import StructureIndex
from src.policy.assertions import SecurityAssertions, resolve_assertion_ref
from src.product.profile import ProductProfile
from src.registry.models import ControlsDraft, DocumentRegistry, ParameterStatus
from src.rules.dsl import validate_rules

VERDICT_KEYS = {"pass", "fail", "verdict", "result", "status_verdict"}


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def validate_document_registry(registry: DocumentRegistry) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    if not registry.documents:
        errors.append("document_registry has no documents")

    present_authoritative = [
        d for d in registry.documents if d.tier == "authoritative" and d.present
    ]
    if len(present_authoritative) < 2:
        errors.append("both authoritative PDFs must be present and parsed")

    for req in registry.requirements:
        if req.source_reference.binding_status != "BINDING":
            errors.append(f"requirement {req.requirement_id} lacks binding source")

    if not registry.classification_references:
        errors.append("Category 6 classification reference missing")

    blocking = [c for c in registry.conflicts if c.human_review_required]
    if blocking:
        warnings.append(f"{len(blocking)} conflict(s) require human review")

    return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)


def _control_has_verdict_keys(obj: Any, path: str = "") -> list[str]:
    """Detect PASS/FAIL/verdict keys that must never appear in controls."""
    found: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_l = str(key).lower()
            current = f"{path}.{key}" if path else str(key)
            if key_l in VERDICT_KEYS or key_l in {"pass", "fail"}:
                # Allow metadata.status == DRAFT/APPROVED; block verdict-like keys
                if key_l == "status" and path.endswith("metadata"):
                    pass
                elif key_l in {"pass", "fail", "verdict", "result"} or (
                    key_l == "status" and isinstance(value, str)
                    and value.upper() in {"PASS", "FAIL"}
                ):
                    found.append(current)
            found.extend(_control_has_verdict_keys(value, current))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            found.extend(_control_has_verdict_keys(item, f"{path}[{i}]"))
    return found


def validate_controls_draft(
    draft: ControlsDraft,
    *,
    parsed_docs: dict[str, ParsedDocument] | None = None,
    structure_indices: dict[str, StructureIndex] | None = None,
    etsi_doc: ParsedDocument | None = None,
    profile: ProductProfile | None = None,
    policy: SecurityAssertions | None = None,
) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    if draft.metadata.status != "DRAFT":
        errors.append("controls registry must have status DRAFT at this stage")

    if not draft.controls:
        errors.append("controls.draft.json has no controls")

    if profile is None:
        errors.append("product profile is required for controls validation")
    if policy is None:
        errors.append("security assertions policy is required for controls validation")

    declared_ports: set[int] = set()
    declared_components: set[str] = {HOST_COMPONENT}
    if profile is not None:
        declared_ports = profile.declared_ports()
        declared_components |= profile.declared_component_names()

    crosswalk_map: dict[str, str] = {}
    if etsi_doc:
        for cw in parse_etsi_crosswalk(etsi_doc):
            key = f"{cw.cra_part}-{cw.cra_point}"
            crosswalk_map[cw.clause_number] = key

    for control in draft.controls:
        if not control.source_traceability.legal_sources:
            errors.append(f"{control.control_id}: missing legal source traceability")

        for src in control.source_traceability.legal_sources:
            if parsed_docs and structure_indices:
                doc = parsed_docs.get(src.document_id)
                idx = structure_indices.get(src.document_id)
                if doc and idx:
                    result = validate_citation(
                        src.source_excerpt,
                        doc,
                        idx,
                        src.source_locator.model_dump(),
                    )
                    errors.extend(
                        f"{control.control_id}: {e}" for e in result.errors
                    )
                    warnings.extend(
                        f"{control.control_id}: {w}" for w in result.warnings
                    )

        for ev in control.evidence_plan:
            if ev.mode.value == "TECHNICAL":
                if not ev.mcp_tool:
                    errors.append(f"{control.control_id}: TECHNICAL evidence missing mcp_tool")
                elif ev.mcp_tool not in MCP_CAPABILITY_CATALOG:
                    if ev.tool_status.value != "REQUIRED_NEW_TOOL":
                        errors.append(
                            f"{control.control_id}: unknown mcp_tool {ev.mcp_tool}"
                        )

            port = ev.parameters.get("port")
            if port is not None and profile is not None:
                try:
                    port_int = int(port)
                except (TypeError, ValueError):
                    errors.append(
                        f"{control.control_id}: invalid port parameter {port!r} "
                        f"on evidence {ev.evidence_key}"
                    )
                else:
                    if port_int not in declared_ports:
                        errors.append(
                            f"{control.control_id}: undeclared port {port_int} "
                            f"on evidence {ev.evidence_key}"
                        )

            path_param = ev.parameters.get("path")
            if path_param is not None:
                if path_param == TO_BE_PROVIDED:
                    if ev.parameter_status != ParameterStatus.TO_BE_PROVIDED:
                        errors.append(
                            f"{control.control_id}: path {TO_BE_PROVIDED} on "
                            f"{ev.evidence_key} must have parameter_status=TO_BE_PROVIDED"
                        )
                elif profile is not None:
                    # Anti-invention: resolved path must not equal a known unresolved profile value
                    unresolved_profile_paths = {
                        profile.configuration.tls_config_file,
                        profile.configuration.application_config,
                        profile.configuration.postgres_config_file,
                    }
                    if (
                        path_param in unresolved_profile_paths
                        and path_param == TO_BE_PROVIDED
                    ):
                        errors.append(
                            f"{control.control_id}: invented path not allowed on "
                            f"{ev.evidence_key}"
                        )

        if control.target_context is not None and profile is not None:
            for comp in control.target_context.components:
                if comp.component not in declared_components:
                    errors.append(
                        f"{control.control_id}: unknown component {comp.component!r}"
                    )
                if comp.port is not None and comp.port not in declared_ports:
                    errors.append(
                        f"{control.control_id}: undeclared port {comp.port} "
                        f"in target_context component {comp.component}"
                    )

        if policy is not None:
            for ref in control.assertion_refs:
                try:
                    resolve_assertion_ref(policy, ref)
                except KeyError as exc:
                    errors.append(
                        f"{control.control_id}: unresolvable assertion_ref {ref!r} ({exc})"
                    )

        verdict_hits = _control_has_verdict_keys(
            control.model_dump(exclude={"evaluation"})
        )
        # Also scan evaluation for explicit PASS/FAIL string values only via top-level keys
        dumped = control.model_dump()
        for banned in ("pass", "fail", "verdict", "PASS", "FAIL"):
            if banned in dumped or banned.lower() in {k.lower() for k in dumped}:
                # model_dump keys are known Control fields; none are pass/fail
                pass
        for hit in verdict_hits:
            if hit.split(".")[-1].lower() in {"pass", "fail", "verdict", "result"}:
                errors.append(
                    f"{control.control_id}: forbidden verdict key at {hit}"
                )

        if control.evaluation.mode.value == "DETERMINISTIC":
            try:
                validate_rules(control.evaluation.rules)
            except Exception as exc:
                errors.append(f"{control.control_id}: invalid rule DSL — {exc}")

    return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)
