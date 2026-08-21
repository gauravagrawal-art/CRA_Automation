"""Approval gate — immutable versioned approved registry."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

from src.config import APPROVED_DIR
from src.registry.models import ApprovalManifest, ControlsDraft


def canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def compute_hash(data: dict | str) -> str:
    if isinstance(data, dict):
        payload = canonical_json(data)
    else:
        payload = data
    return hashlib.sha256(payload.encode()).hexdigest()


def load_controls_draft(path: Path) -> ControlsDraft:
    data = json.loads(path.read_text())
    draft = ControlsDraft.model_validate(data)
    if draft.metadata.status != "DRAFT":
        raise ValueError("Only DRAFT controls may be submitted for approval")
    return draft


def load_approved_controls(path: Path) -> dict:
    data = json.loads(path.read_text())
    if data.get("metadata", {}).get("status") != "APPROVED":
        raise ValueError("File is not an approved controls registry")
    return data


def approve_registry(
    draft: ControlsDraft,
    *,
    approver: str,
    version: str,
    document_registry_hash: str | None = None,
    blocking_conflicts: list | None = None,
) -> tuple[Path, ApprovalManifest]:
    if blocking_conflicts:
        raise ValueError(
            f"Cannot approve: {len(blocking_conflicts)} unresolved blocking conflict(s)"
        )

    approved_data = draft.model_dump()
    approved_data["metadata"]["status"] = "APPROVED"
    approved_data["metadata"]["registry_version"] = version
    approved_data["metadata"]["approved_at"] = datetime.now(timezone.utc).isoformat()
    approved_data["metadata"]["approver"] = approver

    draft_hash = compute_hash(draft.model_dump())
    approved_hash = compute_hash(approved_data)

    APPROVED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = APPROVED_DIR / f"controls.approved.v{version}.json"
    if out_path.exists():
        raise ValueError(f"Approved version {version} already exists")

    out_path.write_text(json.dumps(approved_data, indent=2))
    os.chmod(out_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 0444

    manifest = ApprovalManifest(
        version=version,
        approver=approver,
        approved_at=datetime.now(timezone.utc).isoformat(),
        source_registry_hash=draft_hash,
        approved_registry_hash=approved_hash,
        source_document_registry_hash=document_registry_hash,
    )
    manifest_path = APPROVED_DIR / f"controls.approved.v{version}.manifest.json"
    manifest_path.write_text(manifest.model_dump_json(indent=2))
    os.chmod(manifest_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    return out_path, manifest


def refuse_draft_as_approved(path: Path) -> None:
    data = json.loads(path.read_text())
    if data.get("metadata", {}).get("status") == "DRAFT":
        raise ValueError("DRAFT registry cannot be used as approved input for Flow 2")
