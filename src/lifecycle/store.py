"""Persist and load lifecycle.json beside assessment artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from src.config import ASSESSMENTS_DIR
from src.lifecycle.models import LifecycleDocument


def lifecycle_path(run_id: str, assessments_dir: Path | None = None) -> Path:
    return (assessments_dir or ASSESSMENTS_DIR) / run_id / "lifecycle.json"


def human_evidence_dir(run_id: str, assessments_dir: Path | None = None) -> Path:
    return (assessments_dir or ASSESSMENTS_DIR) / run_id / "human-evidence"


def load_lifecycle(
    run_id: str, assessments_dir: Path | None = None
) -> LifecycleDocument | None:
    path = lifecycle_path(run_id, assessments_dir)
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return LifecycleDocument.model_validate(data)


def save_lifecycle(
    document: LifecycleDocument, assessments_dir: Path | None = None
) -> Path:
    path = lifecycle_path(document.run_id, assessments_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path
