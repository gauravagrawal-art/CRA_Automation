"""Deterministic validation of the remediation inputs.

Flow 4 composes advice from three artifacts that must describe the same scan of
the same target against the same approved baseline. Proving that is application
code, never a question for a model, and a failed check aborts the flow rather
than being reconciled or narrated away.

The registry and evidence half of the work is already done by the Flow 3
preflight, which is reused rather than reimplemented. What is added here is the
assessment: that it is readable, that it was produced from these exact inputs,
and that every control it reports still exists in the approved registry.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.assessment.models import Assessment
from src.assessment.preflight import PreflightError, PreflightResult, preflight
from src.config import SUPPORTED_ASSESSMENT_SCHEMA_VERSIONS
from src.evidence.io import sha256_file


class RemediationPreflightError(Exception):
    """An input is untrusted or inconsistent; remediation must not run."""


@dataclass
class RemediationPreflightResult:
    registry: dict[str, Any]
    registry_hash: str
    registry_path: Path
    assessment: Assessment
    assessment_path: Path
    assessment_sha256: str
    evidence_path: Path
    evidence_sha256: str
    #: The Flow 3 preflight result the registry and evidence checks came from.
    assessment_preflight: PreflightResult


def load_assessment(path: Path) -> Assessment:
    """Read an assessment document written by Flow 3."""
    if not path.exists():
        raise RemediationPreflightError(f"Assessment file not found: {path}")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise RemediationPreflightError(f"Assessment file is not valid JSON: {path}") from exc
    try:
        return Assessment.model_validate(data)
    except Exception as exc:
        raise RemediationPreflightError(
            f"Assessment file does not match the Flow 3 contract: {exc}"
        ) from exc


def _check_schema_version(assessment: Assessment) -> None:
    schema = assessment.metadata.schema_version
    if schema not in SUPPORTED_ASSESSMENT_SCHEMA_VERSIONS:
        raise RemediationPreflightError(
            f"Unsupported assessment schema version '{schema}'; "
            f"remediation supports {sorted(SUPPORTED_ASSESSMENT_SCHEMA_VERSIONS)}"
        )


def _check_baseline(assessment: Assessment, pre: PreflightResult) -> None:
    """The assessment must name the registry it is being remediated against."""
    meta = assessment.metadata
    if meta.registry_hash != pre.registry_hash:
        raise RemediationPreflightError(
            "Assessment was produced against a different registry "
            f"(assessment {meta.registry_hash}, supplied {pre.registry_hash})"
        )

    registry_version = pre.registry.get("metadata", {}).get("registry_version")
    if meta.registry_version != registry_version:
        raise RemediationPreflightError(
            "Assessment registry version does not match the supplied registry "
            f"(assessment {meta.registry_version}, supplied {registry_version})"
        )


def _check_identity(assessment: Assessment, pre: PreflightResult) -> None:
    """The assessment must describe the evidence run it is paired with."""
    meta = assessment.metadata
    if meta.run_id != pre.run.run.run_id:
        raise RemediationPreflightError(
            f"Assessment run ID '{meta.run_id}' does not match evidence run "
            f"'{pre.run.run.run_id}'"
        )
    if meta.target_id != pre.run.run.target_id:
        raise RemediationPreflightError(
            f"Assessment target '{meta.target_id}' does not match evidence target "
            f"'{pre.run.run.target_id}'"
        )
    if meta.evidence_sha256 != pre.evidence_sha256:
        raise RemediationPreflightError(
            "Assessment was produced from different evidence bytes "
            f"(assessment {meta.evidence_sha256}, file {pre.evidence_sha256})"
        )


def _check_controls_known(assessment: Assessment, registry: dict[str, Any]) -> None:
    known = {control.get("control_id") for control in registry.get("controls", [])}
    unknown = sorted(
        result.control_id for result in assessment.results if result.control_id not in known
    )
    if unknown:
        raise RemediationPreflightError(
            "Assessment references control IDs absent from the approved registry: "
            + ", ".join(unknown)
        )


def remediation_preflight(
    *,
    registry_path: Path,
    assessment_path: Path,
    evidence_path: Path,
) -> RemediationPreflightResult:
    """Validate registry, evidence and assessment before any item is composed.

    Raises ``RemediationPreflightError`` on any integrity, identity or schema
    problem. Flow 4 has no partial mode: either the three artifacts agree or
    nothing is written.
    """
    try:
        pre = preflight(registry_path=registry_path, evidence_path=evidence_path)
    except PreflightError as exc:
        raise RemediationPreflightError(str(exc)) from exc

    assessment = load_assessment(assessment_path)
    _check_schema_version(assessment)
    _check_baseline(assessment, pre)
    _check_identity(assessment, pre)
    _check_controls_known(assessment, pre.registry)

    return RemediationPreflightResult(
        registry=pre.registry,
        registry_hash=pre.registry_hash,
        registry_path=registry_path,
        assessment=assessment,
        assessment_path=assessment_path,
        assessment_sha256=sha256_file(assessment_path),
        evidence_path=pre.evidence_path,
        evidence_sha256=pre.evidence_sha256,
        assessment_preflight=pre,
    )
