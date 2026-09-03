"""User-facing labels for the target environment and its applications.

Internal identifiers such as ``nextboss-demo`` stay stable so existing
artifacts, tests, and the demo apply allow-list keep working. The UI and
reports show Target Env + Application instead of those identifiers.
"""

from __future__ import annotations

from src.config import (
    APPLICATIONS,
    DEFAULT_APPLICATION_ID,
    DEMO_TARGET_ID,
    PRODUCT_NAME,
)

APPLICATION_LABELS: dict[str, str] = {key: label for key, label in APPLICATIONS}
APPLICATION_IDS: frozenset[str] = frozenset(APPLICATION_LABELS)
_LABEL_TO_ID: dict[str, str] = {
    label.casefold(): key for key, label in APPLICATIONS
}


def target_env_label(target_id: str | None) -> str:
    """Display name for the target environment.

    The demo mock target is shown as the product name. Any other target id
    is returned unchanged so a future live host is not relabelled by accident.
    """
    if not target_id or target_id == "—":
        return target_id or "—"
    if target_id == DEMO_TARGET_ID:
        return PRODUCT_NAME
    return target_id


def known_application(value: str | None) -> bool:
    if not value:
        return False
    text = value.strip()
    return text in APPLICATION_IDS or text.casefold() in _LABEL_TO_ID


def normalize_application_id(value: str | None, *, default: str = "") -> str:
    """Accept an application id or its display name. Unknown values stay empty."""
    if not value:
        return default
    text = value.strip()
    if text in APPLICATION_IDS:
        return text
    mapped = _LABEL_TO_ID.get(text.casefold())
    if mapped:
        return mapped
    return default


def resolve_application_id(value: str | None) -> str:
    """Require a known application; fall back to the default catalog entry."""
    resolved = normalize_application_id(value, default="")
    return resolved or DEFAULT_APPLICATION_ID


def application_label(application_id: str | None) -> str:
    if not application_id:
        return ""
    resolved = normalize_application_id(application_id)
    return APPLICATION_LABELS.get(resolved, "")


def scope_short(target_id: str | None, application_id: str | None = "") -> str:
    """Compact scope, e.g. ``NetBoss-XT · Router Monitor``."""
    env = target_env_label(target_id)
    app = application_label(application_id)
    if app and env not in {"", "—"}:
        return f"{env} · {app}"
    return env


def scope_caption(
    target_id: str | None,
    application_id: str | None = "",
    verb: str = "Assessment done on",
) -> str:
    """Full scope line for assessment and remediation pages."""
    env = target_env_label(target_id)
    app = application_label(application_id)
    line = f"{verb} Target Env: {env}"
    if app:
        return f"{line} · Application: {app}"
    return line
