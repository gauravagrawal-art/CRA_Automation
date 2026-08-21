"""Argument contracts for every registered MCP capability.

Each tool has an explicit Pydantic model with ``extra="forbid"``, so an
unexpected or malformed argument is rejected before a provider is reached.
There is deliberately no free-form command or query field anywhere here.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, ValidationError

from src.config import (
    MCP_CAPABILITY_CATALOG,
    MCP_MAX_LOG_ENTRIES,
    MCP_MAX_LOG_TIME_RANGE_HOURS,
)
from src.mcp.errors import InvalidArgumentsError


class _ToolArgs(BaseModel):
    model_config = {"extra": "forbid"}


class NoArgs(_ToolArgs):
    pass


class OpenPortsArgs(_ToolArgs):
    """Optional port filter; absent means "all listeners"."""

    port: int | None = Field(default=None, ge=1, le=65535)


class FileArgs(_ToolArgs):
    path: str = Field(min_length=1)


class EndpointArgs(_ToolArgs):
    host: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)


class SecurityLogsArgs(_ToolArgs):
    source: str | None = None
    max_entries: int = Field(default=100, ge=1, le=MCP_MAX_LOG_ENTRIES)
    time_range_hours: int = Field(
        default=24, ge=1, le=MCP_MAX_LOG_TIME_RANGE_HOURS
    )


TOOL_ARGUMENT_SCHEMAS: dict[str, type[_ToolArgs]] = {
    "get_system_info": NoArgs,
    "get_users": NoArgs,
    "get_groups": NoArgs,
    "get_services": NoArgs,
    "get_open_ports": OpenPortsArgs,
    "get_processes": NoArgs,
    "get_file": FileArgs,
    "get_file_permissions": FileArgs,
    "get_network_configuration": NoArgs,
    "get_firewall_rules": NoArgs,
    "get_tls_configuration": EndpointArgs,
    "get_certificates": EndpointArgs,
    "get_installed_packages": NoArgs,
    "get_security_logs": SecurityLogsArgs,
}

# Tools whose call must be addressed at a declared endpoint. The Evidence
# Runner supplies the host from the runtime target profile; the port comes
# from the approved control.
ENDPOINT_TOOLS = frozenset({"get_tls_configuration", "get_certificates"})

# Tools that read a filesystem path and are therefore subject to the allowlist.
PATH_TOOLS = frozenset({"get_file", "get_file_permissions"})


def is_registered_tool(tool: str) -> bool:
    return tool in TOOL_ARGUMENT_SCHEMAS and tool in MCP_CAPABILITY_CATALOG


def validate_arguments(tool: str, parameters: dict[str, Any]) -> dict[str, Any]:
    """Validate raw parameters against the tool contract.

    Returns the normalized argument dict with defaults applied.
    """
    schema = TOOL_ARGUMENT_SCHEMAS.get(tool)
    if schema is None:
        raise InvalidArgumentsError(f"No argument contract registered for tool '{tool}'")
    try:
        return schema.model_validate(parameters).model_dump()
    except ValidationError as exc:
        raise InvalidArgumentsError(
            f"Invalid arguments for '{tool}': {exc.error_count()} validation error(s)"
        ) from exc


def _catalog_consistency() -> None:
    """Every catalog capability must have an argument contract, and vice versa."""
    missing = set(MCP_CAPABILITY_CATALOG) - set(TOOL_ARGUMENT_SCHEMAS)
    extra = set(TOOL_ARGUMENT_SCHEMAS) - set(MCP_CAPABILITY_CATALOG)
    if missing or extra:
        raise RuntimeError(
            f"MCP contract drift — missing: {sorted(missing)}, unregistered: {sorted(extra)}"
        )


_catalog_consistency()
