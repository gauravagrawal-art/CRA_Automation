"""Deterministic validation of the assessment inputs.

Every check here is application code. Whether a registry is trustworthy or an
evidence file belongs to the run being assessed is never a question for a
model. A failed check aborts; it is not narrated away.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.config import (
    SUPPORTED_EVIDENCE_SCHEMA_VERSIONS,
    SUPPORTED_REGISTRY_SCHEMA_VERSIONS,
)
from src.evidence.io import sha256_file
from src.evidence.models import EvidenceRun
from src.evidence.runner import RegistryIntegrityError, load_approved_registry


class PreflightError(Exception):
    """An input is untrusted or inconsistent; the assessment must not run."""


@dataclass
class PreflightResult:
    registry: dict[str, Any]
    registry_hash: str
    registry_path: Path
    run: EvidenceRun
    evidence_path: Path
    evidence_sha256: str
    #: (control_id, evidence_key) pairs present in evidence but not in the
    #: approved registry. Not fatal: the association is dropped and reported.
    unknown_associations: list[tuple[str, str]] = field(default_factory=list)


def load_evidence_run(path: Path) -> EvidenceRun:
    if not path.exists():
        raise PreflightError(f"Evidence file not found: {path}")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise PreflightError(f"Evidence file is not valid JSON: {path}") from exc
    try:
        return EvidenceRun.model_validate(data)
    except Exception as exc:
        raise PreflightError(f"Evidence file does not match the Flow 2 contract: {exc}") from exc


def _check_schema_versions(registry: dict[str, Any], run: EvidenceRun) -> None:
    evidence_schema = run.run.schema_version
    if evidence_schema not in SUPPORTED_EVIDENCE_SCHEMA_VERSIONS:
        raise PreflightError(
            f"Unsupported evidence schema version '{evidence_schema}'; "
            f"this assessment supports {sorted(SUPPORTED_EVIDENCE_SCHEMA_VERSIONS)}"
        )
    registry_schema = registry.get("metadata", {}).get("schema_version")
    if registry_schema not in SUPPORTED_REGISTRY_SCHEMA_VERSIONS:
        raise PreflightError(
            f"Unsupported registry schema version '{registry_schema}'; "
            f"this assessment supports {sorted(SUPPORTED_REGISTRY_SCHEMA_VERSIONS)}"
        )


def _check_identity(
    run: EvidenceRun,
    evidence_path: Path,
    registry_hash: str,
    registry: dict[str, Any],
    expected_target_id: str | None,
) -> None:
    if run.run.registry_hash != registry_hash:
        raise PreflightError(
            "Evidence was collected against a different registry "
            f"(evidence {run.run.registry_hash}, supplied {registry_hash})"
        )

    registry_version = registry.get("metadata", {}).get("registry_version")
    if run.run.registry_version and run.run.registry_version != registry_version:
        raise PreflightError(
            "Evidence registry version does not match the supplied registry "
            f"(evidence {run.run.registry_version}, supplied {registry_version})"
        )

    directory_run_id = evidence_path.parent.name
    if run.run.run_id != directory_run_id:
        raise PreflightError(
            f"Run ID is inconsistent: directory '{directory_run_id}' "
            f"declares run '{run.run.run_id}'"
        )

    if not run.run.target_id:
        raise PreflightError("Evidence run does not declare a target ID")

    if expected_target_id and expected_target_id != run.run.target_id:
        raise PreflightError(
            f"Target ID mismatch: expected '{expected_target_id}', "
            f"evidence declares '{run.run.target_id}'"
        )


def _approved_associations(registry: dict[str, Any]) -> set[tuple[str, str]]:
    approved: set[tuple[str, str]] = set()
    for control in registry.get("controls", []):
        control_id = control.get("control_id", "")
        for item in control.get("evidence_plan", []):
            approved.add((control_id, item.get("evidence_key", "")))
    return approved


def _unknown_associations(
    registry: dict[str, Any], run: EvidenceRun
) -> list[tuple[str, str]]:
    approved = _approved_associations(registry)
    unknown: set[tuple[str, str]] = set()
    for item in run.evidence:
        for requested in item.requested_by:
            pair = (requested.control_id, requested.evidence_key)
            if pair not in approved:
                unknown.add(pair)
    return sorted(unknown)


def preflight(
    *,
    registry_path: Path,
    evidence_path: Path,
    expected_target_id: str | None = None,
) -> PreflightResult:
    """Validate registry and evidence identity before any control is evaluated.

    Raises ``PreflightError`` on registry status, hash, identity or schema
    problems. An evidence association naming an unknown control or evidence key
    is returned for reporting rather than raised, since dropping it cannot
    weaken a verdict.
    """
    try:
        registry, registry_hash = load_approved_registry(registry_path)
    except RegistryIntegrityError as exc:
        raise PreflightError(str(exc)) from exc

    run = load_evidence_run(evidence_path)

    _check_schema_versions(registry, run)
    _check_identity(run, evidence_path, registry_hash, registry, expected_target_id)

    return PreflightResult(
        registry=registry,
        registry_hash=registry_hash,
        registry_path=registry_path,
        run=run,
        evidence_path=evidence_path,
        evidence_sha256=sha256_file(evidence_path),
        unknown_associations=_unknown_associations(registry, run),
    )
