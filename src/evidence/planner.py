"""Turn an approved control registry into a deterministic MCP call plan.

The approved registry *is* the scan plan. Nothing here selects a substitute
tool, infers a missing path, host, port or account name, or reinterprets a
control. Anything that cannot be resolved from the approved control plus the
runtime target profile is refused rather than guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.config import TO_BE_PROVIDED
from src.evidence.targets import TargetProfile
from src.mcp.contracts import ENDPOINT_TOOLS, is_registered_tool
from src.registry.approval import compute_hash

# Approved evidence-plan parameter names that name a runtime endpoint rather
# than carrying a literal address.
SYMBOLIC_PARAM_KEYS = ("target_ref", "endpoint_ref")


@dataclass(frozen=True)
class EvidenceRequest:
    """One `evidence_plan` entry of one approved control."""

    control_id: str
    evidence_key: str
    required: bool
    mode: str
    mcp_tool: str | None
    tool_status: str
    parameter_status: str
    parameters: dict[str, Any]


@dataclass
class PlannedCall:
    """A unique MCP call plus every approved request that asked for it."""

    call_id: str
    call_key: str
    tool: str
    parameters: dict[str, Any]
    requested_by: list[EvidenceRequest] = field(default_factory=list)


@dataclass
class SkippedRequest:
    """An approved request that will not reach the MCP."""

    request: EvidenceRequest
    status: str
    reason_code: str
    message: str


@dataclass
class CollectionPlan:
    calls: list[PlannedCall] = field(default_factory=list)
    skipped: list[SkippedRequest] = field(default_factory=list)
    total_requests: int = 0
    technical_requests: int = 0
    documentary_requests: int = 0


class ParameterResolutionError(Exception):
    """Raised when a parameter cannot be resolved without guessing."""

    def __init__(self, message: str, reason_code: str = "PARAMETER_UNRESOLVED") -> None:
        super().__init__(message)
        self.message = message
        self.reason_code = reason_code


def iter_evidence_requests(registry: dict[str, Any]) -> list[EvidenceRequest]:
    """Enumerate every evidence-plan entry in registry order."""
    requests: list[EvidenceRequest] = []
    for control in registry.get("controls", []):
        control_id = control.get("control_id", "")
        for item in control.get("evidence_plan", []):
            requests.append(
                EvidenceRequest(
                    control_id=control_id,
                    evidence_key=item.get("evidence_key", ""),
                    required=bool(item.get("required", True)),
                    mode=item.get("mode", ""),
                    mcp_tool=item.get("mcp_tool"),
                    tool_status=item.get("tool_status", ""),
                    parameter_status=item.get("parameter_status", ""),
                    parameters=dict(item.get("parameters") or {}),
                )
            )
    return requests


def _contains_unprovided(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip() == TO_BE_PROVIDED
    if isinstance(value, dict):
        return any(_contains_unprovided(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_unprovided(item) for item in value)
    return False


def resolve_parameters(
    request: EvidenceRequest, profile: TargetProfile
) -> dict[str, Any]:
    """Resolve approved parameters against the runtime target profile.

    Ports and paths always come from the approved control. Only the runtime
    address is contributed by the target profile.
    """
    if request.parameter_status != "RESOLVED":
        raise ParameterResolutionError(
            f"Approved parameter_status is '{request.parameter_status}'; "
            "Flow 2 does not supply a substitute value."
        )

    resolved: dict[str, Any] = {}
    endpoint_ref: str | None = None

    for key, value in request.parameters.items():
        if _contains_unprovided(value):
            raise ParameterResolutionError(
                f"Approved parameter '{key}' is {TO_BE_PROVIDED}; "
                "a default value is never inferred."
            )
        if key in SYMBOLIC_PARAM_KEYS:
            if not isinstance(value, str) or not value:
                raise ParameterResolutionError(
                    f"Symbolic reference '{key}' is not a usable endpoint name."
                )
            endpoint_ref = value
            continue
        resolved[key] = value

    if endpoint_ref is not None and endpoint_ref not in profile.endpoints:
        raise ParameterResolutionError(
            f"Endpoint reference '{endpoint_ref}' is not declared in target profile "
            f"'{profile.target_id}'."
        )

    tool = request.mcp_tool or ""
    if tool in ENDPOINT_TOOLS:
        # The approved control supplies the product port; the target profile
        # supplies where this scan runs.
        resolved.setdefault("host", profile.endpoint_host(endpoint_ref))
        if "port" not in resolved:
            raise ParameterResolutionError(
                f"Tool '{tool}' requires a port and the approved control supplies none."
            )
    elif endpoint_ref is not None:
        resolved.setdefault("host", profile.endpoint_host(endpoint_ref))

    return resolved


def call_key_for(
    *, target_id: str, provider: str, tool: str, parameters: dict[str, Any]
) -> str:
    """Canonical deduplication key.

    Materially different resolved parameters produce different keys, so calls
    are only merged when they are genuinely identical.
    """
    return compute_hash(
        {
            "target_id": target_id,
            "provider": provider,
            "tool": tool,
            "parameters": parameters,
        }
    )


def build_plan(registry: dict[str, Any], profile: TargetProfile) -> CollectionPlan:
    """Select collectable requests, resolve parameters, and deduplicate calls."""
    plan = CollectionPlan()
    by_key: dict[str, PlannedCall] = {}

    for request in iter_evidence_requests(registry):
        plan.total_requests += 1

        if request.mode != "TECHNICAL":
            plan.documentary_requests += 1
            plan.skipped.append(
                SkippedRequest(
                    request=request,
                    status="NOT_COLLECTED",
                    reason_code="DOCUMENTARY_OR_HUMAN",
                    message=(
                        "Evidence mode is DOCUMENTARY_OR_HUMAN; it is not executed "
                        "by the evidence runner."
                    ),
                )
            )
            continue

        plan.technical_requests += 1

        if request.tool_status != "AVAILABLE":
            plan.skipped.append(
                SkippedRequest(
                    request=request,
                    status="TOOL_UNAVAILABLE",
                    reason_code="REQUIRED_NEW_TOOL",
                    message=(
                        f"Approved tool_status is '{request.tool_status}'; "
                        "no substitute tool is selected."
                    ),
                )
            )
            continue

        if not request.mcp_tool or not is_registered_tool(request.mcp_tool):
            plan.skipped.append(
                SkippedRequest(
                    request=request,
                    status="TOOL_UNAVAILABLE",
                    reason_code="TOOL_NOT_REGISTERED",
                    message=(
                        f"MCP tool '{request.mcp_tool}' is not a registered capability."
                    ),
                )
            )
            continue

        try:
            parameters = resolve_parameters(request, profile)
        except ParameterResolutionError as exc:
            plan.skipped.append(
                SkippedRequest(
                    request=request,
                    status="NOT_COLLECTED",
                    reason_code=exc.reason_code,
                    message=exc.message,
                )
            )
            continue

        key = call_key_for(
            target_id=profile.target_id,
            provider=profile.provider,
            tool=request.mcp_tool,
            parameters=parameters,
        )
        existing = by_key.get(key)
        if existing is None:
            existing = PlannedCall(
                call_id=f"CALL-{len(by_key) + 1:04d}",
                call_key=key,
                tool=request.mcp_tool,
                parameters=parameters,
            )
            by_key[key] = existing
            plan.calls.append(existing)
        existing.requested_by.append(request)

    return plan
