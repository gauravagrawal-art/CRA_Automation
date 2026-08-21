"""Secret redaction applied before any payload leaves the MCP boundary.

Redaction runs at the provider boundary, so the Evidence Runner never holds an
unredacted copy and no unsanitized bytes can reach disk. If redaction cannot be
completed, the payload is discarded rather than persisted.

Only matching keys and known secret patterns are touched; other
security-relevant evidence is passed through unchanged.
"""

from __future__ import annotations

import re
from typing import Any

from src.config import (
    REDACTION_KEY_PATTERNS,
    REDACTION_PLACEHOLDER,
    REDACTION_VALUE_PATTERNS,
)
from src.mcp.errors import RedactionFailedError

_MAX_DEPTH = 64

_KEY_RE = re.compile("|".join(REDACTION_KEY_PATTERNS), re.IGNORECASE)
_VALUE_RES = [re.compile(pattern) for pattern in REDACTION_VALUE_PATTERNS]


def _redact_string(value: str) -> str:
    for pattern in _VALUE_RES:
        value = pattern.sub(REDACTION_PLACEHOLDER, value)
    return value


def _walk(value: Any, depth: int) -> Any:
    if depth > _MAX_DEPTH:
        raise RedactionFailedError(
            f"Payload nesting exceeds {_MAX_DEPTH} levels; refusing to persist"
        )
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if _KEY_RE.search(str(key)):
                result[str(key)] = REDACTION_PLACEHOLDER
            else:
                result[str(key)] = _walk(item, depth + 1)
        return result
    if isinstance(value, list):
        return [_walk(item, depth + 1) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    # Unknown types cannot be inspected for secrets, so they are not persisted.
    raise RedactionFailedError(
        f"Unsupported value type '{type(value).__name__}' in tool result"
    )


def redact(payload: Any) -> Any:
    """Return a sanitized copy of ``payload``; fail closed on any error."""
    try:
        return _walk(payload, 0)
    except RedactionFailedError:
        raise
    except Exception as exc:  # noqa: BLE001 - any failure here must fail closed
        raise RedactionFailedError(f"Redaction failed: {exc}") from exc


def contains_secret_material(payload: Any) -> bool:
    """Post-condition check used by tests and the fail-closed guard."""
    if isinstance(payload, dict):
        for key, item in payload.items():
            if _KEY_RE.search(str(key)) and item != REDACTION_PLACEHOLDER:
                return True
            if contains_secret_material(item):
                return True
        return False
    if isinstance(payload, list):
        return any(contains_secret_material(item) for item in payload)
    if isinstance(payload, str):
        return any(pattern.search(payload) for pattern in _VALUE_RES)
    return False
