"""The deterministic Evidence Runner.

Reads an approved control registry, executes only the MCP capabilities the
approved evidence plan asks for, and writes a hashed, auditable evidence
document.

The runner never loads `policy/security_assertions.yaml`, never reads CRA or
ETSI documents, and never emits a compliance verdict. Missing evidence is
recorded as a collection status; deciding what that means is the job of the
downstream assessment layer.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from src.config import EVIDENCE_DIR
from src.evidence.io import canonical_sha256, write_json_artifact
from src.evidence.models import (
    CollectionError,
    CollectionStatus,
    CollectionSummary,
    EvidenceItem,
    EvidenceRun,
    ReasonCode,
    RequestedBy,
    RunMetadata,
)
from src.evidence.normalize import NormalizationError, normalize
from src.evidence.planner import (
    CollectionPlan,
    EvidenceRequest,
    PlannedCall,
    SkippedRequest,
    build_plan,
)
from src.evidence.targets import TargetProfile, load_target_profile
from src.mcp.errors import McpError
from src.mcp.providers.base import Provider
from src.mcp.providers.mock import MockProvider
from src.mcp.redaction import redact
from src.mcp.server import ToolRegistry
from src.registry.approval import compute_hash


class RegistryIntegrityError(Exception):
    """Raised when the approved registry cannot be trusted as a scan plan."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_approved_registry(path: Path) -> tuple[dict[str, Any], str]:
    """Load an approved registry and verify status plus recorded hash.

    Returns ``(registry, registry_hash)``.
    """
    if not path.exists():
        raise RegistryIntegrityError(f"Approved registry not found: {path}")

    data = json.loads(path.read_text())
    status = data.get("metadata", {}).get("status")
    if status != "APPROVED":
        raise RegistryIntegrityError(
            f"Registry status is '{status}'; Flow 2 only accepts APPROVED registries"
        )

    registry_hash = compute_hash(data)

    manifest_path = path.with_name(path.stem + ".manifest.json")
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        recorded = manifest.get("approved_registry_hash")
        if recorded and recorded != registry_hash:
            raise RegistryIntegrityError(
                "Approved registry hash does not match its manifest "
                f"(recorded {recorded}, computed {registry_hash})"
            )

    return data, registry_hash


def build_provider(profile: TargetProfile) -> Provider:
    if profile.provider == "mock":
        return MockProvider(profile.target_id, profile.environment)
    if profile.provider == "ssh":
        raise NotImplementedError(
            "SSHProvider is not part of this baseline. Implement it behind the "
            "Provider interface so the evidence contract stays unchanged."
        )
    raise ValueError(f"Unsupported provider '{profile.provider}'")


def make_run_id(registry_hash: str, target_profile_hash: str, started_at: str) -> str:
    digest = compute_hash(
        {
            "registry_hash": registry_hash,
            "target_profile_hash": target_profile_hash,
            "started_at": started_at,
        }
    )
    stamp = started_at.replace("-", "").replace(":", "").split(".")[0].replace("+0000", "")
    return f"RUN-{stamp}-{digest[:8]}"


def _requested_by(requests: list[EvidenceRequest]) -> list[RequestedBy]:
    return [
        RequestedBy(
            control_id=request.control_id,
            evidence_key=request.evidence_key,
            required=request.required,
        )
        for request in requests
    ]


def _summarize(
    plan: CollectionPlan,
    registry: dict[str, Any],
    items: list[EvidenceItem],
    errors: list[CollectionError],
) -> CollectionSummary:
    by_status: dict[str, int] = {}
    by_reason: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    for item in items:
        by_status[item.status.value] = by_status.get(item.status.value, 0) + 1
        if item.status_reason_code is not None:
            key = item.status_reason_code.value
            by_reason[key] = by_reason.get(key, 0) + 1
        by_tool[item.tool] = by_tool.get(item.tool, 0) + 1

    collectable = sum(len(call.requested_by) for call in plan.calls)
    return CollectionSummary(
        controls_in_registry=len(registry.get("controls", [])),
        evidence_requests_total=plan.total_requests,
        evidence_requests_technical=plan.technical_requests,
        evidence_requests_documentary=plan.documentary_requests,
        evidence_requests_collectable=collectable,
        mcp_calls_planned=len(plan.calls),
        mcp_calls_deduplicated=max(collectable - len(plan.calls), 0),
        evidence_items=len(items),
        collection_errors=len(errors),
        by_status=dict(sorted(by_status.items())),
        by_reason_code=dict(sorted(by_reason.items())),
        by_tool=dict(sorted(by_tool.items())),
    )


def _skipped_item(
    skipped: SkippedRequest, index: int, profile: TargetProfile, timestamp: str
) -> tuple[EvidenceItem, CollectionError]:
    call_id = f"NOCALL-{index:04d}"
    status = CollectionStatus(skipped.status)
    reason = ReasonCode(skipped.reason_code)
    requested_by = _requested_by([skipped.request])
    item = EvidenceItem(
        evidence_id=f"EV-{index:04d}",
        call_id=call_id,
        requested_by=requested_by,
        tool=skipped.request.mcp_tool or "none",
        parameters_redacted=redact(skipped.request.parameters),
        provider=profile.provider,
        target_id=profile.target_id,
        collected_at=timestamp,
        status=status,
        status_reason_code=reason,
        status_message=skipped.message,
    )
    error = CollectionError(
        call_id=call_id,
        requested_by=requested_by,
        tool=skipped.request.mcp_tool,
        status=status,
        reason_code=reason,
        message=skipped.message,
    )
    return item, error


def _execute_call(
    call: PlannedCall,
    index: int,
    registry_tools: ToolRegistry,
    profile: TargetProfile,
    raw_dir: Path,
    timestamp: str,
) -> tuple[EvidenceItem, CollectionError | None]:
    evidence_id = f"EV-{index:04d}"
    requested_by = _requested_by(call.requested_by)
    base = {
        "evidence_id": evidence_id,
        "call_id": call.call_id,
        "requested_by": requested_by,
        "tool": call.tool,
        "parameters_redacted": redact(call.parameters),
        "provider": profile.provider,
        "target_id": profile.target_id,
    }

    try:
        result = registry_tools.call(call.tool, call.parameters)
    except McpError as exc:
        status = CollectionStatus(exc.status)
        reason = ReasonCode(exc.reason_code)
        item = EvidenceItem(
            **base,
            collected_at=timestamp,
            status=status,
            status_reason_code=reason,
            status_message=exc.message,
        )
        error = CollectionError(
            call_id=call.call_id,
            requested_by=requested_by,
            tool=call.tool,
            status=status,
            reason_code=reason,
            message=exc.message,
        )
        return item, error

    # The result is already sanitized; these are the exact persisted bytes.
    artifact_path = raw_dir / f"{evidence_id}.json"
    _, raw_sha256 = write_json_artifact(artifact_path, result.model_dump())

    try:
        normalized = normalize(call.tool, result.arguments, result.data, result.collected_at)
    except NormalizationError as exc:
        item = EvidenceItem(
            **base,
            collected_at=result.collected_at,
            status=CollectionStatus.PARSE_ERROR,
            status_reason_code=ReasonCode.NORMALIZATION_FAILED,
            status_message=str(exc),
            raw_artifact_ref=f"raw/{evidence_id}.json",
            raw_sha256=raw_sha256,
            normalized=None,
        )
        error = CollectionError(
            call_id=call.call_id,
            requested_by=requested_by,
            tool=call.tool,
            status=CollectionStatus.PARSE_ERROR,
            reason_code=ReasonCode.NORMALIZATION_FAILED,
            message=str(exc),
        )
        return item, error

    item = EvidenceItem(
        **base,
        collected_at=result.collected_at,
        status=CollectionStatus.COLLECTED,
        raw_artifact_ref=f"raw/{evidence_id}.json",
        raw_sha256=raw_sha256,
        normalized=normalized,
        normalized_sha256=canonical_sha256(normalized),
    )
    return item, None


def collect_evidence(
    *,
    registry_path: Path,
    target_path: Path,
    output_dir: Path | None = None,
    run_id: str | None = None,
    provider_override: str | None = None,
    scenario_override: str | None = None,
    clock: Callable[[], str] | None = None,
) -> tuple[Path, EvidenceRun]:
    """Execute the approved evidence plan and write `evidence.json`.

    Returns ``(run_directory, evidence_run)``.
    """
    now = clock or _utc_now
    started_at = now()

    registry, registry_hash = load_approved_registry(registry_path)
    profile, target_profile_hash = load_target_profile(target_path)

    if provider_override:
        profile = profile.model_copy(update={"provider": provider_override})
    if scenario_override:
        profile = profile.model_copy(update={"environment": scenario_override})

    resolved_run_id = run_id or make_run_id(registry_hash, target_profile_hash, started_at)
    run_dir = (output_dir or EVIDENCE_DIR) / resolved_run_id
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    plan = build_plan(registry, profile)

    provider = build_provider(profile)
    tools = ToolRegistry(provider, clock=now)

    items: list[EvidenceItem] = []
    errors: list[CollectionError] = []
    index = 0

    try:
        for call in plan.calls:
            index += 1
            item, error = _execute_call(call, index, tools, profile, raw_dir, started_at)
            items.append(item)
            if error is not None:
                errors.append(error)
    finally:
        tools.close()

    for skipped in plan.skipped:
        index += 1
        item, error = _skipped_item(skipped, index, profile, started_at)
        items.append(item)
        errors.append(error)

    run = EvidenceRun(
        run=RunMetadata(
            run_id=resolved_run_id,
            target_id=profile.target_id,
            registry_version=registry.get("metadata", {}).get("registry_version", ""),
            registry_hash=registry_hash,
            registry_path=str(registry_path),
            target_profile_hash=target_profile_hash,
            provider=profile.provider,
            started_at=started_at,
            completed_at=now(),
        ),
        evidence=items,
        collection_errors=errors,
        summary=_summarize(plan, registry, items, errors),
    )

    write_json_artifact(run_dir / "evidence.json", run.model_dump(mode="json"))
    return run_dir, run
