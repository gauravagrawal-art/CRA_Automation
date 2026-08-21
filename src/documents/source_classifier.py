"""Source authority classification from document content fingerprints."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.documents.loader import DocumentInventoryItem
from src.documents.parser import ParsedDocument


@dataclass
class ClassifiedDocument:
    document_id: str
    filename: str
    title: str
    issuer: str
    source_type: str
    binding_status: str
    document_status: str
    authority_level: int  # 1-4
    version_date: str | None = None
    sha256: str | None = None
    page_count: int | None = None
    present: bool = True
    metadata_conflicts: list[dict] = field(default_factory=list)


def _first_pages_text(doc: ParsedDocument, n: int = 3) -> str:
    return "\n".join(p.cleaned_text for p in doc.pages[:n])


def classify_document(
    item: DocumentInventoryItem,
    parsed: ParsedDocument | None = None,
) -> ClassifiedDocument:
    if not item.present or parsed is None:
        return ClassifiedDocument(
            document_id=item.document_id,
            filename=item.filename,
            title="Unknown (absent)",
            issuer="Unknown",
            source_type="absent",
            binding_status="UNKNOWN",
            document_status="ABSENT",
            authority_level=0,
            present=False,
        )

    sample = _first_pages_text(parsed)
    conflicts: list[dict] = []

    # Specific fingerprints first (avoid false positives from cross-references)

    if re.search(r"C\(2026\)\s*5252|Commission guidance on the application", sample, re.I):
        return ClassifiedDocument(
            document_id=item.document_id,
            filename=item.filename,
            title="Commission guidance on the application of Regulation (EU) 2024/2847",
            issuer="European Commission",
            source_type="GUIDANCE",
            binding_status="NON_BINDING",
            document_status="GUIDANCE",
            authority_level=2,
            version_date="2026-07-27",
            sha256=item.sha256,
            page_count=item.page_count,
            present=True,
        )

    if re.search(r"C\(2025\)\s*618|standardisation request to the European", sample, re.I):
        return ClassifiedDocument(
            document_id=item.document_id,
            filename=item.filename,
            title="Commission standardisation request C(2025) 618",
            issuer="European Commission",
            source_type="STANDARDISATION_REQUEST",
            binding_status="NON_BINDING",
            document_status="FINAL",
            authority_level=4,
            version_date="2025-02-03",
            sha256=item.sha256,
            page_count=item.page_count,
            present=True,
        )

    if re.search(r"Draft ETSI EN 304 621|DEN/CYBER-EUS-009", sample, re.I):
        body_version = None
        vm = re.search(r"Draft ETSI EN 304 621\s+V([\d.]+)", sample)
        if vm:
            body_version = vm.group(1)
        filename_version = "1.0.5" if "V1.0.5" in item.filename else None
        doc_status = "ON_APPROVAL"
        if body_version and filename_version and body_version != filename_version:
            conflicts.append(
                {
                    "conflict_id": "ETSI-VERSION-MISMATCH",
                    "description": (
                        f"Filename declares V{filename_version} but document body "
                        f"declares V{body_version}"
                    ),
                    "filename_version": filename_version,
                    "body_version": body_version,
                    "resolution": "Record both; use body version as primary metadata",
                }
            )
        return ClassifiedDocument(
            document_id=item.document_id,
            filename=item.filename,
            title="ETSI EN 304 621 — Cybersecurity requirements for Network Management systems",
            issuer="ETSI",
            source_type="TECHNICAL_STANDARD",
            binding_status="NON_BINDING",
            document_status=doc_status,
            authority_level=3,
            version_date=body_version or filename_version,
            sha256=item.sha256,
            page_count=item.page_count,
            present=True,
            metadata_conflicts=conflicts,
        )

    if re.search(r"2025/2392|technical description of the categories", sample, re.I):
        return ClassifiedDocument(
            document_id=item.document_id,
            filename=item.filename,
            title="Commission Implementing Regulation (EU) 2025/2392",
            issuer="European Commission",
            source_type="IMPLEMENTING_REGULATION",
            binding_status="BINDING",
            document_status="FINAL",
            authority_level=1,
            version_date="2025-11-28",
            sha256=item.sha256,
            page_count=item.page_count,
            present=True,
        )

    if re.search(r"02024R2847|REGULATION \(EU\) 2024/2847|Cyber Resilience Act", sample, re.I):
        return ClassifiedDocument(
            document_id=item.document_id,
            filename=item.filename,
            title="Regulation (EU) 2024/2847 (Cyber Resilience Act)",
            issuer="European Parliament and Council",
            source_type="REGULATION",
            binding_status="BINDING",
            document_status="FINAL",
            authority_level=1,
            version_date="2024-10-23",
            sha256=item.sha256,
            page_count=item.page_count,
            present=True,
        )

    return ClassifiedDocument(
        document_id=item.document_id,
        filename=item.filename,
        title="Unclassified document",
        issuer="Unknown",
        source_type="UNKNOWN",
        binding_status="UNKNOWN",
        document_status="UNKNOWN",
        authority_level=0,
        sha256=item.sha256,
        page_count=item.page_count,
        present=True,
    )
