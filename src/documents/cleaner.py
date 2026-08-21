"""Strip consolidation markers, running headers, and page furniture."""

from __future__ import annotations

import re

# CRA consolidation / corrigendum markers
_CRA_MARKER_RE = re.compile(r"[▼►]\s*[BC]\d?\s*")
_CRA_RUNNING_HEADER_RE = re.compile(
    r"02024R2847\s*[—\-]\s*EN\s*[—\-]\s*\d{2}\.\d{2}\.\d{4}\s*[—\-]\s*[\d.]+\s*[—\-]\s*\d+"
)
_CRA_CORRIGENDUM_RE = re.compile(
    r"Corrected by:.*?(?=REGULATION|CHAPTER|Article|\Z)",
    re.DOTALL | re.IGNORECASE,
)

# OJ / ELI footers
_OJ_ELI_FOOTER_RE = re.compile(
    r"ELI:\s*http://data\.europa\.eu/eli/[^\n]+\n?\d+/\d+",
    re.IGNORECASE,
)
_OJ_HEADER_RE = re.compile(
    r"Official Journal\s*\n\s*of the European Union\s*\n\s*EN\s*\n\s*L series",
    re.IGNORECASE,
)

# ETSI page furniture
_ETSI_HEADER_RE = re.compile(
    r"ETSI\s*\nDraft ETSI EN 304 621[^\n]*\n\d+",
    re.IGNORECASE,
)
_ETSI_FOOTER_RE = re.compile(
    r"Draft ETSI EN 304 621[^\n]*\t\d+",
    re.IGNORECASE,
)

_PAGE_BREAK_RE = re.compile(r"--\s*\d+\s+of\s+\d+\s*--", re.IGNORECASE)


def clean_page_text(text: str, document_id: str = "") -> str:
    """Clean a single page of extracted PDF text."""
    result = text

    if document_id.startswith("CRA-2024") or "02024R2847" in text:
        result = _CRA_CORRIGENDUM_RE.sub("", result)
        result = _CRA_MARKER_RE.sub("", result)
        result = _CRA_RUNNING_HEADER_RE.sub("", result)

    if document_id.startswith("CRA-2025") or "2025/2392" in text:
        result = _OJ_ELI_FOOTER_RE.sub("", result)
        result = _OJ_HEADER_RE.sub("", result)

    if document_id.startswith("ETSI") or "ETSI EN 304 621" in text:
        result = _ETSI_HEADER_RE.sub("", result)
        result = _ETSI_FOOTER_RE.sub("", result)

    result = _PAGE_BREAK_RE.sub("", result)
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result.strip()
