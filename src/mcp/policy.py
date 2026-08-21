"""Enforcement of the Infrastructure MCP policy.

Path allowlisting, output-size caps and log bounds are applied here so that a
path carried by an approved control still has to pass an independent check
before any read happens.
"""

from __future__ import annotations

import fnmatch
import json
from typing import Any

from src.config import (
    MCP_MAX_FILE_BYTES,
    MCP_MAX_LOG_ENTRIES,
    MCP_MAX_LOG_TIME_RANGE_HOURS,
    MCP_MAX_OUTPUT_BYTES,
    MCP_PATH_ALLOWLIST,
    TO_BE_PROVIDED,
)
from src.mcp.errors import OutputLimitExceededError, PathNotAllowedError


def is_path_allowed(path: str) -> bool:
    if not path or path == TO_BE_PROVIDED:
        return False
    if not path.startswith("/"):
        return False
    if ".." in path.split("/"):
        return False
    if "\x00" in path:
        return False
    return any(fnmatch.fnmatch(path, pattern) for pattern in MCP_PATH_ALLOWLIST)


def enforce_path_allowlist(path: str) -> str:
    """Raise unless the path is absolute, traversal-free and allowlisted."""
    if not is_path_allowed(path):
        raise PathNotAllowedError(
            f"Path '{path}' is not permitted by MCP path policy"
        )
    return path


def enforce_file_size(path: str, size_bytes: int) -> None:
    if size_bytes > MCP_MAX_FILE_BYTES:
        raise OutputLimitExceededError(
            f"File '{path}' is {size_bytes} bytes, exceeding the "
            f"{MCP_MAX_FILE_BYTES} byte read limit"
        )


def enforce_log_bounds(max_entries: int, time_range_hours: int) -> None:
    if max_entries > MCP_MAX_LOG_ENTRIES:
        raise OutputLimitExceededError(
            f"Requested {max_entries} log entries, limit is {MCP_MAX_LOG_ENTRIES}"
        )
    if time_range_hours > MCP_MAX_LOG_TIME_RANGE_HOURS:
        raise OutputLimitExceededError(
            f"Requested a {time_range_hours}h log window, limit is "
            f"{MCP_MAX_LOG_TIME_RANGE_HOURS}h"
        )


def enforce_output_size(tool: str, payload: Any) -> int:
    """Cap the serialized size of a tool result. Returns the measured size."""
    size = len(json.dumps(payload, sort_keys=True, default=str).encode("utf-8"))
    if size > MCP_MAX_OUTPUT_BYTES:
        raise OutputLimitExceededError(
            f"Result of '{tool}' is {size} bytes, exceeding the "
            f"{MCP_MAX_OUTPUT_BYTES} byte output limit"
        )
    return size
