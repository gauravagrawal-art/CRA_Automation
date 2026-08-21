"""Flow 1 workflow steps, shared by the CLI and the web UI.

The validation pipeline and the review summary used to live inside the CLI
command bodies. They are here so both front ends reach the same result: these
functions decide, and the caller renders.

Nothing in this module prints or exits. A precondition failure raises
``RegistryServiceError`` carrying the message the user should see.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from src.agents.agent1 import run_agent1
from src.agents.coverage import AREA_MATRIX
from src.config import APPROVED_DIR, REGISTRY_DIR
from src.documents.loader import load_inventory
from src.documents.parser import parse_pdf
from src.documents.structure import build_structure_index
from src.policy.assertions import load_security_assertions
from src.product.profile import ProductProfile, load_product_profile
from src.registry.approval import approve_registry, compute_hash, load_controls_draft
from src.registry.models import (
    ApprovalManifest,
    ConflictEntry,
    ControlsDraft,
    DocumentRegistry,
)
from src.registry.validator import validate_controls_draft, validate_document_registry
from src.registry.versioning import latest_approved_path, list_approved_versions


class RegistryServiceError(RuntimeError):
    """A precondition failed. The message is user-facing."""


def document_registry_path() -> Path:
    return REGISTRY_DIR / "document_registry.json"


def draft_path() -> Path:
    return REGISTRY_DIR / "controls.draft.json"


def approved_path(version: str) -> Path:
    return APPROVED_DIR / f"controls.approved.v{version}.json"


def manifest_path(version: str) -> Path:
    return APPROVED_DIR / f"controls.approved.v{version}.manifest.json"


def resolve_registry_path(explicit: Path | None = None) -> Path:
    """The approved registry a scan should run against.

    Centralised so the CLI, the UI and every action agree on what "the
    registry" means when the caller did not name one.
    """
    path = explicit or latest_approved_path()
    if path is None:
        raise RegistryServiceError(
            "No approved registry found. Run 'approve-registry' first."
        )
    return path


def _require_registries() -> tuple[Path, Path]:
    doc_path = document_registry_path()
    ctrl_path = draft_path()
    if not doc_path.exists() or not ctrl_path.exists():
        raise RegistryServiceError("Registries not found. Run 'ingest' first.")
    return doc_path, ctrl_path


def load_document_registry() -> DocumentRegistry:
    path = document_registry_path()
    if not path.exists():
        raise RegistryServiceError("Registries not found. Run 'ingest' first.")
    return DocumentRegistry.model_validate(json.loads(path.read_text()))


def load_draft() -> ControlsDraft:
    path = draft_path()
    if not path.exists():
        raise RegistryServiceError("Registries not found. Run 'ingest' first.")
    return ControlsDraft.model_validate(json.loads(path.read_text()))


def load_approved(path: Path | None = None) -> ControlsDraft:
    """Read an approved registry through the same contract as the draft."""
    target = resolve_registry_path(path)
    return ControlsDraft.model_validate(json.loads(target.read_text()))


def load_manifest(version: str) -> ApprovalManifest | None:
    path = manifest_path(version)
    if not path.exists():
        return None
    return ApprovalManifest.model_validate(json.loads(path.read_text()))


@dataclass
class BuildResult:
    documents: int
    requirements: int
    controls: int
    document_registry_path: Path
    draft_path: Path


def build_draft() -> BuildResult:
    """Run Agent 1: ingest the source documents and write the draft registries."""
    doc_registry, controls = run_agent1()
    return BuildResult(
        documents=len(doc_registry.documents),
        requirements=len(doc_registry.requirements),
        controls=len(controls.controls),
        document_registry_path=document_registry_path(),
        draft_path=draft_path(),
    )


@dataclass
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def validate_all() -> ValidationReport:
    """Validate both draft registries against schemas, citations and rules.

    Source PDFs are re-parsed so citation excerpts are checked against the
    documents themselves rather than against the registry's own copy of them.
    """
    doc_path, ctrl_path = _require_registries()

    try:
        profile, _ = load_product_profile()
    except Exception as exc:
        raise RegistryServiceError(f"Product profile load failed: {exc}") from exc

    try:
        policy, _ = load_security_assertions()
    except Exception as exc:
        raise RegistryServiceError(f"Security assertions load failed: {exc}") from exc

    doc_registry = DocumentRegistry.model_validate(json.loads(doc_path.read_text()))
    controls = ControlsDraft.model_validate(json.loads(ctrl_path.read_text()))

    inventory = load_inventory()
    parsed = {}
    indices = {}
    for item in inventory.authoritative + inventory.supporting:
        if item.present and item.path:
            doc = parse_pdf(item.path, item.document_id)
            parsed[item.document_id] = doc
            indices[item.document_id] = build_structure_index(doc)

    doc_result = validate_document_registry(doc_registry)
    ctrl_result = validate_controls_draft(
        controls,
        parsed_docs=parsed,
        structure_indices=indices,
        etsi_doc=parsed.get("ETSI-EN-304-621"),
        profile=profile,
        policy=policy,
    )

    return ValidationReport(
        errors=doc_result.errors + ctrl_result.errors,
        warnings=doc_result.warnings + ctrl_result.warnings,
    )


def point_key_from_title(title: str) -> str | None:
    """Extract the CRA point from a control title such as ``CRA I-2-b: ...``."""
    if title.startswith("CRA "):
        rest = title[4:]
        return rest.split(":", 1)[0].strip()
    return None


@dataclass
class CoverageRow:
    area_id: str
    name: str
    cra_points: str
    controls: int
    evidence_items: int
    assertion_refs: int


@dataclass
class ReviewSummary:
    documents: list = field(default_factory=list)
    requirements: int = 0
    controls: int = 0
    conflicts: list[ConflictEntry] = field(default_factory=list)
    human_review_items: int = 0
    unresolved_items: int = 0
    controls_flagged: int = 0
    coverage: list[CoverageRow] = field(default_factory=list)


def review_summary() -> ReviewSummary:
    """The human-review picture of the draft registries, including area coverage."""
    _require_registries()
    doc_registry = load_document_registry()
    controls = load_draft()

    coverage: list[CoverageRow] = []
    for area in AREA_MATRIX:
        matching: list[str] = []
        evidence_count = 0
        ref_count = 0
        for control in controls.controls:
            point = point_key_from_title(control.title)
            if point and point in area.cra_points:
                matching.append(control.control_id)
                evidence_count += len(control.evidence_plan)
                ref_count += len(
                    [r for r in control.assertion_refs if r in area.assertion_refs]
                )
        coverage.append(
            CoverageRow(
                area_id=area.area_id,
                name=area.name,
                cra_points=", ".join(area.cra_points),
                controls=len(set(matching)),
                evidence_items=evidence_count,
                assertion_refs=ref_count,
            )
        )

    return ReviewSummary(
        documents=list(doc_registry.documents),
        requirements=len(doc_registry.requirements),
        controls=len(controls.controls),
        conflicts=list(doc_registry.conflicts),
        human_review_items=len(doc_registry.human_review_items),
        unresolved_items=len(doc_registry.unresolved_items),
        controls_flagged=sum(1 for c in controls.controls if c.human_review_required),
        coverage=coverage,
    )


def blocking_conflicts() -> list[ConflictEntry]:
    """Document conflicts that must be resolved or explicitly overridden."""
    doc_path = document_registry_path()
    if not doc_path.exists():
        return []
    registry = DocumentRegistry.model_validate(json.loads(doc_path.read_text()))
    return [c for c in registry.conflicts if c.human_review_required]


@dataclass
class ApprovalResult:
    path: Path
    manifest: ApprovalManifest


def approve(*, approver: str, version: str, allow_conflicts: bool = False) -> ApprovalResult:
    """Freeze the draft into an immutable versioned baseline.

    Refuses while a blocking document conflict is unresolved unless the caller
    explicitly overrides, and never overwrites an existing approved version.
    """
    ctrl_path = draft_path()
    if not ctrl_path.exists():
        raise RegistryServiceError("controls.draft.json not found.")

    if approved_path(version).exists():
        raise RegistryServiceError(
            f"Approved registry v{version} already exists and is immutable. "
            "Choose a new version number."
        )

    draft = load_controls_draft(ctrl_path)

    doc_path = document_registry_path()
    doc_hash = None
    if doc_path.exists():
        doc_hash = compute_hash(json.loads(doc_path.read_text()))

    blocking = blocking_conflicts()
    if blocking and not allow_conflicts:
        raise RegistryServiceError(
            f"Cannot approve: {len(blocking)} unresolved blocking conflict(s). "
            "Use --allow-conflicts to override."
        )

    out_path, manifest = approve_registry(
        draft,
        approver=approver,
        version=version,
        document_registry_hash=doc_hash,
        blocking_conflicts=blocking if not allow_conflicts else None,
    )
    return ApprovalResult(path=out_path, manifest=manifest)


@dataclass
class RegistryState:
    """What registries exist right now and whether a scan may run."""

    draft_exists: bool = False
    draft_controls: int = 0
    draft_generated_at: str = ""
    approved_versions: list[str] = field(default_factory=list)
    latest_version: str | None = None
    latest_path: Path | None = None
    latest_hash: str | None = None
    approver: str = ""
    approved_at: str = ""

    @property
    def status(self) -> str:
        if self.latest_version:
            return "APPROVED"
        if self.draft_exists:
            return "DRAFT"
        return "NONE"

    @property
    def scannable(self) -> bool:
        return self.latest_version is not None

    @property
    def label(self) -> str:
        if self.latest_version:
            return f"v{self.latest_version} APPROVED"
        if self.draft_exists:
            return "DRAFT (not approved)"
        return "Not built"


def registry_state() -> RegistryState:
    """Read the registry situation from disk without raising."""
    state = RegistryState()

    path = draft_path()
    if path.exists():
        try:
            draft = ControlsDraft.model_validate(json.loads(path.read_text()))
        except (OSError, ValueError):
            return state
        state.draft_exists = True
        state.draft_controls = len(draft.controls)
        state.draft_generated_at = draft.metadata.generated_at

    state.approved_versions = list_approved_versions()
    if state.approved_versions:
        state.latest_version = state.approved_versions[-1]
        state.latest_path = approved_path(state.latest_version)
        manifest = load_manifest(state.latest_version)
        if manifest is not None:
            state.latest_hash = manifest.approved_registry_hash
            state.approver = manifest.approver
            state.approved_at = manifest.approved_at
    return state


def suggest_next_version() -> str:
    """Propose the next baseline version: a minor bump on the newest approved one."""
    versions = list_approved_versions()
    if not versions:
        return "1.0.0"
    try:
        major, minor, _patch = (int(part) for part in versions[-1].split("."))
    except ValueError:
        return "1.0.0"
    return f"{major}.{minor + 1}.0"


def product_context() -> tuple[ProductProfile | None, str]:
    """The product profile for the Sources page, or the reason it is unavailable."""
    try:
        profile, _ = load_product_profile()
    except Exception as exc:
        return None, str(exc)
    return profile, ""
