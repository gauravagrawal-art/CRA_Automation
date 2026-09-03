"""Target-scoped demo overlay state for allow-listed fixture patches.

Stored under assessments/.demo-state/<target_id>.json. Not an assessment
artifact and never listed in the UI download allowlist.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from src.config import ASSESSMENTS_DIR, DEMO_STATE_DIR, DEMO_TARGET_ID


def demo_state_path(
    target_id: str = DEMO_TARGET_ID, *, root: Path | None = None
) -> Path:
    base = root if root is not None else DEMO_STATE_DIR
    if root is not None and root.name != ".demo-state":
        # When tests pass assessments_dir, keep overlay beside that tree.
        base = root / ".demo-state"
    return base / f"{target_id}.json"


def load_demo_state(
    target_id: str = DEMO_TARGET_ID, *, root: Path | None = None
) -> dict[str, Any]:
    path = demo_state_path(target_id, root=root)
    if not path.exists():
        return {"target_id": target_id, "operations": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {"target_id": target_id, "operations": {}}
    data.setdefault("target_id", target_id)
    data.setdefault("operations", {})
    return data


def save_demo_state(
    document: dict[str, Any], *, root: Path | None = None
) -> Path:
    target_id = str(document.get("target_id") or DEMO_TARGET_ID)
    path = demo_state_path(target_id, root=root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def overlay_hash(document: dict[str, Any]) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def deep_merge(base: Any, patch: Any) -> Any:
    """Merge patch into a deep copy of base. Lists and scalars are replaced."""
    if isinstance(base, dict) and isinstance(patch, dict):
        out = copy.deepcopy(base)
        for key, value in patch.items():
            if key in out:
                out[key] = deep_merge(out[key], value)
            else:
                out[key] = copy.deepcopy(value)
        return out
    return copy.deepcopy(patch)


def apply_operations_to_fixture(
    fixture: dict[str, Any], operations: dict[str, Any]
) -> dict[str, Any]:
    """Apply all operation patches to a fixture copy (fixtures stay immutable)."""
    merged = copy.deepcopy(fixture)
    for _op_id, record in sorted(operations.items()):
        if not isinstance(record, dict):
            continue
        patches = record.get("patches") or {}
        if isinstance(patches, dict):
            merged = deep_merge(merged, patches)
    return merged


def upsert_operation(
    target_id: str,
    operation_id: str,
    *,
    control_id: str,
    patches: dict[str, Any],
    applied_at: str,
    root: Path | None = None,
) -> tuple[dict[str, Any], str]:
    doc = load_demo_state(target_id, root=root)
    ops = dict(doc.get("operations") or {})
    ops[operation_id] = {
        "control_id": control_id,
        "applied_at": applied_at,
        "patches": patches,
    }
    doc["operations"] = ops
    save_demo_state(doc, root=root)
    return doc, overlay_hash(doc)


def remove_operation(
    target_id: str,
    operation_id: str,
    *,
    root: Path | None = None,
) -> dict[str, Any]:
    doc = load_demo_state(target_id, root=root)
    ops = dict(doc.get("operations") or {})
    ops.pop(operation_id, None)
    doc["operations"] = ops
    save_demo_state(doc, root=root)
    return doc


def assessments_demo_root(assessments_dir: Path | None = None) -> Path:
    """Root for demo-state when tests isolate assessments under a temp dir."""
    if assessments_dir is None:
        return DEMO_STATE_DIR
    # Prefer sibling .demo-state under the assessments parent so it is shared
    # across runs of the same target, matching production layout under ASSESSMENTS_DIR.
    if assessments_dir == ASSESSMENTS_DIR:
        return DEMO_STATE_DIR
    return assessments_dir / ".demo-state"
