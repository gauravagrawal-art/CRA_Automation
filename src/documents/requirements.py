"""Extract binding CRA requirements from Annex I."""

from __future__ import annotations

import re

from src.documents.parser import ParsedDocument
from src.registry.models import RequirementEntry, SourceLocator, SourceReference


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _find_annex_i(full_text: str) -> str | None:
    match = re.search(
        r"ANNEX I\s+ESSENTIAL CYBERSECURITY REQUIREMENTS(.*)",
        full_text,
        re.S | re.I,
    )
    return match.group(1) if match else None


def _page_for_text(doc: ParsedDocument, snippet: str) -> int | None:
    normalized = _normalize(snippet[:120])
    for page in doc.pages:
        if normalized in _normalize(page.cleaned_text):
            return page.pdf_page
    return None


def extract_cra_requirements(doc: ParsedDocument) -> list[RequirementEntry]:
    annex = _find_annex_i(doc.full_cleaned_text)
    if not annex:
        return []

    entries: list[RequirementEntry] = []

    # Part I point (1)
    m1 = re.search(
        r"\(1\)\s+Products with digital elements shall be designed, developed\s+and produced\s+"
        r"in such a way that they ensure an appropriate level of cybersec\s*urity based\s+on the risks\.",
        annex,
        re.S | re.I,
    )
    if m1:
        text = _normalize(m1.group(0))
        page = _page_for_text(doc, text) or 61
        entries.append(
            _make_entry("CRA-ANNEX-I-PART-I-I-1", "I", "1", None, text, page)
        )

    # Part I point (2) lettered sub-points
    m2_start = re.search(
        r"\(2\)\s+On the basis of the cybersecurity risk assessment",
        annex,
        re.I,
    )
    part_ii_start = re.search(r"Part II\s+Vulnerability handling", annex, re.I)
    if m2_start and part_ii_start:
        block = annex[m2_start.start() : part_ii_start.start()]
        for letter in "abcdefghijklm":
            pat = rf"\({letter}\)\s+(.+?)(?=\([a-z]\)\s+|\Z)"
            m = re.search(pat, block, re.S | re.I)
            if m:
                text = _normalize(f"({letter}) {m.group(1)}")
                page = _page_for_text(doc, text) or 61
                entries.append(
                    _make_entry(
                        f"CRA-ANNEX-I-PART-I-I-2-{letter}",
                        "I",
                        "2",
                        letter,
                        text,
                        page,
                    )
                )

    # Part II points (1)-(8)
    if part_ii_start:
        part_ii = annex[part_ii_start.end() :]
        for num in range(1, 9):
            pat = rf"\({num}\)\s+(.+?)(?=\({num + 1}\)\s+|\Z)"
            m = re.search(pat, part_ii, re.S)
            if m:
                text = _normalize(f"({num}) {m.group(1)}")
                page = _page_for_text(doc, text) or 62
                entries.append(
                    _make_entry(
                        f"CRA-ANNEX-I-PART-II-II-{num}",
                        "II",
                        str(num),
                        None,
                        text,
                        page,
                    )
                )

    return entries


def _make_entry(
    requirement_id: str,
    part: str,
    point: str,
    clause: str | None,
    text: str,
    page: int,
) -> RequirementEntry:
    point_label = f"{point}-{clause}" if clause else point
    return RequirementEntry(
        requirement_id=requirement_id,
        legal_requirement_text=text,
        normalized_requirement=(
            f"CRA Annex I Part {part} requirement ({point_label}) "
            f"for product cybersecurity"
        ),
        source_reference=SourceReference(
            document_id="CRA-2024-2847",
            source_locator=SourceLocator(
                page=page,
                annex="I",
                part=part,
                paragraph=point,
                clause=clause,
            ),
            source_excerpt=text[:500],
            normalized_summary=f"Annex I Part {part} ({point_label}) essential cybersecurity requirement",
            binding_status="BINDING",
        ),
        cra_annex="I",
        cra_part=part,
        cra_point=point,
    )


def extract_category6_reference(doc: ParsedDocument) -> SourceReference | None:
    full = doc.full_cleaned_text
    match = re.search(
        r"6\.\s*Network\s+manage\s*ment\s+systems\s+"
        r"(Products with digital elements.+?)"
        r"(?=7\.\s|8\.\s|Boot managers|\Z)",
        full,
        re.S | re.I,
    )
    if not match:
        # Fallback: flexible whitespace
        match = re.search(
            r"6\.\s*Network.{0,20}management.{0,5}systems\s+"
            r"(Products with digital elements.+?)"
            r"(?=\n7\.|\Z)",
            full,
            re.S | re.I,
        )
    if not match:
        return None
    excerpt = _normalize(f"6. Network management systems {match.group(1)}")
    page = _page_for_text(doc, "Network manage ment systems") or 5
    return SourceReference(
        document_id="CRA-2025-2392",
        source_locator=SourceLocator(page=page, annex="I", section="6"),
        source_excerpt=excerpt[:500],
        normalized_summary=(
            "Category 6 Class I technical description: Network Management Systems"
        ),
        binding_status="BINDING",
    )
