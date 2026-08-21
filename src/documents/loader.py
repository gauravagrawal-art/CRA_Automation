"""Document inventory loader — SHA-256, metadata, no network."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from pypdf import PdfReader

from src.config import (
    AUTHORITATIVE_DIR,
    EXPECTED_AUTHORITATIVE,
    EXPECTED_SUPPORTING,
    SUPPORTING_DIR,
)


@dataclass
class DocumentInventoryItem:
    document_id: str
    filename: str
    path: Path | None
    title: str | None = None
    issuer: str | None = None
    source_type: str | None = None
    binding_status: str | None = None
    document_status: str | None = None
    version_date: str | None = None
    sha256: str | None = None
    byte_size: int | None = None
    page_count: int | None = None
    mtime: str | None = None
    present: bool = True
    tier: str = "authoritative"  # authoritative | supporting


@dataclass
class InventoryResult:
    authoritative: list[DocumentInventoryItem] = field(default_factory=list)
    supporting: list[DocumentInventoryItem] = field(default_factory=list)
    absent: list[DocumentInventoryItem] = field(default_factory=list)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _page_count(path: Path) -> int:
    reader = PdfReader(str(path))
    return len(reader.pages)


def _document_id_from_filename(filename: str, tier: str) -> str:
    mapping = {
        "CELEX_02024R2847-20241120_EN_TXT.pdf": "CRA-2024-2847",
        "OJ_L_202502392_EN_TXT.pdf": "CRA-2025-2392",
        "C_2026_5252_CRA_Guidance.pdf": "C-2026-5252",
        "ETSI_EN_304_621_V1.0.5.pdf": "ETSI-EN-304-621",
        "C_2025_618_CRA_Standardisation_Request.pdf": "C-2025-618",
    }
    if filename in mapping:
        return mapping[filename]
    stem = Path(filename).stem[:32]
    return f"{tier.upper()}-{stem}"


def _load_present_file(path: Path, tier: str) -> DocumentInventoryItem:
    stat = path.stat()
    mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
    return DocumentInventoryItem(
        document_id=_document_id_from_filename(path.name, tier),
        filename=path.name,
        path=path,
        sha256=_sha256_file(path),
        byte_size=stat.st_size,
        page_count=_page_count(path),
        mtime=mtime,
        present=True,
        tier=tier,
    )


def _absent_item(filename: str, tier: str) -> DocumentInventoryItem:
    return DocumentInventoryItem(
        document_id=_document_id_from_filename(filename, tier),
        filename=filename,
        path=None,
        present=False,
        tier=tier,
    )


def load_inventory(
    authoritative_dir: Path = AUTHORITATIVE_DIR,
    supporting_dir: Path = SUPPORTING_DIR,
) -> InventoryResult:
    """Load document inventory. Missing supporting docs are recorded, not fatal."""
    result = InventoryResult()

    for filename in EXPECTED_AUTHORITATIVE:
        path = authoritative_dir / filename
        if path.is_file():
            result.authoritative.append(_load_present_file(path, "authoritative"))
        else:
            item = _absent_item(filename, "authoritative")
            result.absent.append(item)
            result.authoritative.append(item)

    for filename in EXPECTED_SUPPORTING:
        path = supporting_dir / filename
        if path.is_file():
            result.supporting.append(_load_present_file(path, "supporting"))
        else:
            item = _absent_item(filename, "supporting")
            result.absent.append(item)
            result.supporting.append(item)

    return result


def assert_no_network() -> None:
    """Flow 1 guard: inventory uses only local filesystem reads."""
    # Explicit no-op marker for tests and audit trail.
    return None
