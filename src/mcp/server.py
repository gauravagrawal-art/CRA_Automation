"""The Infrastructure MCP tool registry.

``ToolRegistry.call`` is the only way into a provider. It rejects unregistered
tools, validates arguments against the tool contract, applies path/size/bound
policy, then redacts the result before returning it.

The registry makes no compliance decision and returns no verdict.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from pydantic import BaseModel, Field

from src.mcp.contracts import PATH_TOOLS, is_registered_tool, validate_arguments
from src.mcp.errors import McpError, ToolNotRegisteredError
from src.mcp.policy import (
    enforce_log_bounds,
    enforce_output_size,
    enforce_path_allowlist,
)
from src.mcp.providers.base import Provider
from src.mcp.redaction import redact


class ToolResult(BaseModel):
    """Envelope returned for every successful capability invocation."""

    tool: str
    target_id: str
    provider: str
    collected_at: str
    collection_status: str = "COLLECTED"
    arguments: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)


class ToolRegistry:
    """Dispatches validated calls to a single provider."""

    def __init__(self, provider: Provider, *, clock: Callable[[], str] | None = None) -> None:
        self.provider = provider
        self._clock = clock or (lambda: datetime.now(timezone.utc).isoformat())

    @property
    def registered_tools(self) -> list[str]:
        from src.mcp.contracts import TOOL_ARGUMENT_SCHEMAS

        return sorted(TOOL_ARGUMENT_SCHEMAS)

    def call(self, tool: str, parameters: dict[str, Any] | None = None) -> ToolResult:
        if not is_registered_tool(tool):
            raise ToolNotRegisteredError(
                f"'{tool}' is not a registered MCP capability"
            )

        args = validate_arguments(tool, parameters or {})
        self._apply_policy(tool, args)

        handler = getattr(self.provider, tool, None)
        if handler is None or not callable(handler):
            raise ToolNotRegisteredError(
                f"Provider '{self.provider.name}' does not implement '{tool}'"
            )

        try:
            data = handler(**args)
        except McpError:
            raise
        except Exception as exc:  # noqa: BLE001 - provider faults become collection errors
            raise McpError(f"Provider '{self.provider.name}' failed on '{tool}': {exc}") from exc

        sanitized = redact(data)
        enforce_output_size(tool, sanitized)

        return ToolResult(
            tool=tool,
            target_id=self.provider.target_id,
            provider=self.provider.name,
            collected_at=self._clock(),
            arguments=redact(args),
            data=sanitized,
        )

    def _apply_policy(self, tool: str, args: dict[str, Any]) -> None:
        if tool in PATH_TOOLS:
            enforce_path_allowlist(args["path"])
        if tool == "get_security_logs":
            enforce_log_bounds(args["max_entries"], args["time_range_hours"])

    def close(self) -> None:
        self.provider.close()
