"""PDF text extraction and page-level cleaning."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from pypdf import PdfReader

from src.documents.cleaner import clean_page_text


@dataclass
class PageText:
    pdf_page: int  # 1-based
    document_page_label: str | None
    raw_text: str
    cleaned_text: str


@dataclass
class ParsedDocument:
    document_id: str
    filename: str
    path: Path
    pages: list[PageText] = field(default_factory=list)

    @property
    def full_cleaned_text(self) -> str:
        return "\n".join(p.cleaned_text for p in self.pages)

    def page_text(self, pdf_page: int) -> str | None:
        for p in self.pages:
            if p.pdf_page == pdf_page:
                return p.cleaned_text
        return None


_PAGE_LABEL_RE = re.compile(r"--\s*(\d+)\s+of\s+(\d+)\s*--", re.IGNORECASE)


def _extract_page_label(text: str) -> str | None:
    match = _PAGE_LABEL_RE.search(text)
    if match:
        return f"{match.group(1)}/{match.group(2)}"
    return None


def parse_pdf(path: Path, document_id: str) -> ParsedDocument:
    reader = PdfReader(str(path))
    doc = ParsedDocument(document_id=document_id, filename=path.name, path=path)
    for idx, page in enumerate(reader.pages, start=1):
        raw = page.extract_text() or ""
        label = _extract_page_label(raw)
        cleaned = clean_page_text(raw, document_id=document_id)
        doc.pages.append(
            PageText(
                pdf_page=idx,
                document_page_label=label,
                raw_text=raw,
                cleaned_text=cleaned,
            )
        )
    return doc
