"""Document structure index and segmenters."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.documents.parser import ParsedDocument


@dataclass
class StructureNode:
    kind: str
    label: str
    pdf_page: int
    start_char: int
    end_char: int | None = None
    parent: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class StructureIndex:
    document_id: str
    nodes: list[StructureNode] = field(default_factory=list)

    def resolve_locator(
        self,
        *,
        page: int | None,
        article: str | None = None,
        annex: str | None = None,
        part: str | None = None,
        section: str | None = None,
        paragraph: str | None = None,
        clause: str | None = None,
    ) -> StructureNode | None:
        if page is None:
            return None
        candidates = [n for n in self.nodes if n.pdf_page == page]
        if not candidates:
            return None

        def _match(node: StructureNode) -> bool:
            meta = node.metadata
            if article and meta.get("article") != article:
                return False
            if annex and meta.get("annex") != annex:
                return False
            if part and meta.get("part") != part:
                return False
            if section and meta.get("section") != section:
                return False
            if paragraph and meta.get("paragraph") != paragraph:
                return False
            if clause and meta.get("clause") != clause:
                return False
            return True

        for node in candidates:
            if _match(node):
                return node
        return candidates[0] if candidates else None


_ARTICLE_RE = re.compile(r"^Article\s+(\d+)\s*$", re.MULTILINE)
_ANNEX_RE = re.compile(r"^ANNEX\s+([IVXLC]+)\s*$", re.MULTILINE)
_PART_RE = re.compile(r"^Part\s+(I{1,3}|IV|V|VI{0,3}|IX|X)\b", re.MULTILINE | re.IGNORECASE)
_CHAPTER_RE = re.compile(r"^CHAPTER\s+([IVXLC]+)\s*$", re.MULTILINE)
_POINT_RE = re.compile(r"^\((\d+)\)\s+", re.MULTILINE)
_LETTER_POINT_RE = re.compile(r"^\(([a-z])\)\s+", re.MULTILINE)
_ETSI_CLAUSE_RE = re.compile(r"^(\d+(?:\.\d+)*)\s+([^\n]+)$", re.MULTILINE)
_ETSI_REQ_RE = re.compile(r"^•\s+([A-Z0-9_-]+-\d+)\s+", re.MULTILINE)
_SECTION_RE = re.compile(r"^(\d+(?:\.\d+)*)\s+([^\n]+)$", re.MULTILINE)
_CAT6_RE = re.compile(
    r"6\.\s*Network\s+manage\s*ment\s+systems\s+"
    r"(Products with digital elements.+?)"
    r"(?=7\.\s|\Z)",
    re.DOTALL | re.IGNORECASE,
)
_CLASS_ROW_RE = re.compile(
    r"^(\d+)\.\s+([^\n]+)\n\s*(Products with digital elements[^\n]+(?:\n[^\n\d][^\n]*)*)",
    re.MULTILINE | re.IGNORECASE,
)


def _char_offset(full_text: str, match_start: int) -> int:
    return match_start


def build_structure_index(doc: ParsedDocument) -> StructureIndex:
    index = StructureIndex(document_id=doc.document_id)
    full = doc.full_cleaned_text

    if doc.document_id == "CRA-2024-2847":
        _index_cra(doc, full, index)
    elif doc.document_id == "CRA-2025-2392":
        _index_oj_classification(doc, full, index)
    elif doc.document_id == "ETSI-EN-304-621":
        _index_etsi(doc, full, index)
    elif doc.document_id == "C-2026-5252":
        _index_commission_guidance(doc, full, index)
    elif doc.document_id == "C-2025-618":
        _index_standardisation(doc, full, index)
    else:
        _index_generic(doc, full, index)

    return index


def _page_for_offset(doc: ParsedDocument, char_offset: int) -> int:
    cumulative = 0
    for page in doc.pages:
        length = len(page.cleaned_text) + 1
        if char_offset < cumulative + length:
            return page.pdf_page
        cumulative += length
    return doc.pages[-1].pdf_page if doc.pages else 1


def _index_cra(doc: ParsedDocument, full: str, index: StructureIndex) -> None:
    for m in _CHAPTER_RE.finditer(full):
        index.nodes.append(
            StructureNode(
                kind="chapter",
                label=f"CHAPTER {m.group(1)}",
                pdf_page=_page_for_offset(doc, m.start()),
                start_char=m.start(),
                metadata={"chapter": m.group(1)},
            )
        )
    for m in _ARTICLE_RE.finditer(full):
        index.nodes.append(
            StructureNode(
                kind="article",
                label=f"Article {m.group(1)}",
                pdf_page=_page_for_offset(doc, m.start()),
                start_char=m.start(),
                metadata={"article": m.group(1)},
            )
        )
    for m in _ANNEX_RE.finditer(full):
        index.nodes.append(
            StructureNode(
                kind="annex",
                label=f"ANNEX {m.group(1)}",
                pdf_page=_page_for_offset(doc, m.start()),
                start_char=m.start(),
                metadata={"annex": m.group(1)},
            )
        )
    for m in _PART_RE.finditer(full):
        index.nodes.append(
            StructureNode(
                kind="part",
                label=f"Part {m.group(1)}",
                pdf_page=_page_for_offset(doc, m.start()),
                start_char=m.start(),
                metadata={"part": m.group(1).upper()},
            )
        )
    for m in _POINT_RE.finditer(full):
        index.nodes.append(
            StructureNode(
                kind="paragraph",
                label=f"({m.group(1)})",
                pdf_page=_page_for_offset(doc, m.start()),
                start_char=m.start(),
                metadata={"paragraph": m.group(1)},
            )
        )
    for m in _LETTER_POINT_RE.finditer(full):
        index.nodes.append(
            StructureNode(
                kind="letter_point",
                label=f"({m.group(1)})",
                pdf_page=_page_for_offset(doc, m.start()),
                start_char=m.start(),
                metadata={"paragraph": m.group(1)},
            )
        )


def _index_oj_classification(doc: ParsedDocument, full: str, index: StructureIndex) -> None:
    for m in _ARTICLE_RE.finditer(full):
        index.nodes.append(
            StructureNode(
                kind="article",
                label=f"Article {m.group(1)}",
                pdf_page=_page_for_offset(doc, m.start()),
                start_char=m.start(),
                metadata={"article": m.group(1)},
            )
        )
    for m in _ANNEX_RE.finditer(full):
        index.nodes.append(
            StructureNode(
                kind="annex",
                label=f"ANNEX {m.group(1)}",
                pdf_page=_page_for_offset(doc, m.start()),
                start_char=m.start(),
                metadata={"annex": m.group(1)},
            )
        )
    for m in _CLASS_ROW_RE.finditer(full):
        cat_num = m.group(1)
        index.nodes.append(
            StructureNode(
                kind="category",
                label=f"Category {cat_num}: {m.group(2).strip()}",
                pdf_page=_page_for_offset(doc, m.start()),
                start_char=m.start(),
                metadata={
                    "category": cat_num,
                    "category_name": m.group(2).strip(),
                    "technical_description": m.group(3).strip(),
                },
            )
        )
    cat6 = _CAT6_RE.search(full)
    if cat6:
        index.nodes.append(
            StructureNode(
                kind="category",
                label="Category 6: Network management systems",
                pdf_page=_page_for_offset(doc, cat6.start()),
                start_char=cat6.start(),
                metadata={
                    "category": "6",
                    "category_name": "Network management systems",
                    "technical_description": cat6.group(1).strip(),
                    "class": "I",
                },
            )
        )


def _index_etsi(doc: ParsedDocument, full: str, index: StructureIndex) -> None:
    for m in _ETSI_CLAUSE_RE.finditer(full):
        index.nodes.append(
            StructureNode(
                kind="clause",
                label=f"{m.group(1)} {m.group(2).strip()}",
                pdf_page=_page_for_offset(doc, m.start()),
                start_char=m.start(),
                metadata={"section": m.group(1), "title": m.group(2).strip()},
            )
        )
    for m in _ETSI_REQ_RE.finditer(full):
        req_id = m.group(1)
        index.nodes.append(
            StructureNode(
                kind="requirement",
                label=req_id,
                pdf_page=_page_for_offset(doc, m.start()),
                start_char=m.start(),
                metadata={"clause": req_id},
            )
        )


def _index_commission_guidance(doc: ParsedDocument, full: str, index: StructureIndex) -> None:
    for m in _SECTION_RE.finditer(full):
        if m.group(1).count(".") <= 2:
            index.nodes.append(
                StructureNode(
                    kind="section",
                    label=f"{m.group(1)} {m.group(2).strip()}",
                    pdf_page=_page_for_offset(doc, m.start()),
                    start_char=m.start(),
                    metadata={"section": m.group(1)},
                )
            )


def _index_standardisation(doc: ParsedDocument, full: str, index: StructureIndex) -> None:
    _index_commission_guidance(doc, full, index)


def _index_generic(doc: ParsedDocument, full: str, index: StructureIndex) -> None:
    for m in _SECTION_RE.finditer(full):
        index.nodes.append(
            StructureNode(
                kind="section",
                label=f"{m.group(1)} {m.group(2).strip()}",
                pdf_page=_page_for_offset(doc, m.start()),
                start_char=m.start(),
                metadata={"section": m.group(1)},
            )
        )
