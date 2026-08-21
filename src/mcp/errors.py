"""Error types raised by the MCP boundary.

Each error carries the collection status and reason code the Evidence Runner
should record. The strings match the ``CollectionStatus`` / ``ReasonCode``
vocabularies without importing them, keeping the MCP layer independent of the
evidence document contract.
"""

from __future__ import annotations


class McpError(Exception):
    """Base class for every failure surfaced across the MCP boundary."""

    status = "NOT_COLLECTED"
    reason_code = "PROVIDER_ERROR"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ToolNotRegisteredError(McpError):
    status = "TOOL_UNAVAILABLE"
    reason_code = "TOOL_NOT_REGISTERED"


class InvalidArgumentsError(McpError):
    status = "NOT_COLLECTED"
    reason_code = "INVALID_TOOL_PARAMETERS"


class PathNotAllowedError(McpError):
    status = "NOT_COLLECTED"
    reason_code = "PATH_NOT_ALLOWED"


class OutputLimitExceededError(McpError):
    status = "NOT_COLLECTED"
    reason_code = "OUTPUT_LIMIT_EXCEEDED"


class RedactionFailedError(McpError):
    """Raised when redaction cannot be completed safely.

    The payload is discarded rather than persisted in a possibly unsafe state.
    """

    status = "NOT_COLLECTED"
    reason_code = "REDACTION_FAILED"


class TargetUnreachableError(McpError):
    status = "TARGET_UNREACHABLE"
    reason_code = "TARGET_UNREACHABLE"


class PermissionDeniedError(McpError):
    status = "PERMISSION_DENIED"
    reason_code = "PERMISSION_DENIED"


class SourceUnavailableError(McpError):
    """The requested file or log source does not exist on the target."""

    status = "NOT_COLLECTED"
    reason_code = "SOURCE_UNAVAILABLE"
