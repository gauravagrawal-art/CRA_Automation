"""Registry versioning utilities."""

from __future__ import annotations

import re
from pathlib import Path

from src.config import APPROVED_DIR


def list_approved_versions() -> list[str]:
    versions: list[str] = []
    if not APPROVED_DIR.exists():
        return versions
    for path in APPROVED_DIR.glob("controls.approved.v*.json"):
        m = re.search(r"v(\d+\.\d+\.\d+)\.json$", path.name)
        if m:
            versions.append(m.group(1))
    return sorted(versions)


def latest_approved_path() -> Path | None:
    versions = list_approved_versions()
    if not versions:
        return None
    return APPROVED_DIR / f"controls.approved.v{versions[-1]}.json"
