"""Filesystem and hashing helpers for evidence artifacts.

Raw artifacts are hashed over the exact bytes written to disk so the recorded
digest can be reproduced by re-reading the file.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from src.registry.approval import canonical_json


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(obj: Any) -> str:
    """SHA-256 over deterministic canonical JSON."""
    return hashlib.sha256(canonical_json_any(obj).encode("utf-8")).hexdigest()


def canonical_json_any(obj: Any) -> str:
    """Canonical JSON for any JSON-serializable value.

    ``src.registry.approval.canonical_json`` is typed for dicts; evidence
    normalization also hashes lists and scalars.
    """
    if isinstance(obj, dict):
        return canonical_json(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    """Write via a temp file in the same directory, then rename into place."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".part")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def atomic_write_text(path: Path, text: str) -> bytes:
    """Write text atomically as UTF-8 and return the exact bytes written."""
    payload = text.encode("utf-8")
    atomic_write_bytes(path, payload)
    return payload


def write_json_artifact(path: Path, obj: Any, *, indent: int = 2) -> tuple[bytes, str]:
    """Persist a JSON artifact and return ``(bytes_written, sha256)``."""
    payload = atomic_write_text(path, json.dumps(obj, indent=indent, sort_keys=True))
    return payload, sha256_bytes(payload)
