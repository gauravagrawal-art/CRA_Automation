"""ETSI EN 304 621 CRA crosswalk parser."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.documents.parser import ParsedDocument


@dataclass
class EtsiRequirement:
    requirement_id: str
    text: str
    applicability_conditions: list[str] = field(default_factory=list)
    pdf_page: int | None = None


@dataclass
class EtsiClauseCrosswalk:
    clause_number: str
    clause_title: str
    cra_annex: str
    cra_part: str
    cra_point: str
    requirements: list[EtsiRequirement] = field(default_factory=list)
    assessment_criteria_ids: list[str] = field(default_factory=list)


_CRA_ADDRESS_RE = re.compile(
    r"This clause addresses the requirements in the CRA \[i\.1\] Annex I Part (I|II) \((\d+)\) \(([a-z\d]+)\)",
    re.I,
)
_REQ_ID_RE = re.compile(r"^•\s+([A-Z0-9_-]+-\d+)\s+(.+)$", re.MULTILINE)
_APPLICABILITY_RE = re.compile(
    r"^\s*-\s+This requirement applies to (.+?)(?=\n\s*-\s+This requirement|\n\s*NOTE|\n•|\n\d+\.\d|\Z)",
    re.S | re.MULTILINE,
)
_CLAUSE_HEADER_RE = re.compile(r"^(\d+\.\d+)\s+([^\n]+)$", re.MULTILINE)
_ASSESSMENT_ID_RE = re.compile(r"\b([A-Z_]+-\d+)\b")


def _page_for_offset(doc: ParsedDocument, char_offset: int) -> int:
    cumulative = 0
    for page in doc.pages:
        length = len(page.cleaned_text) + 1
        if char_offset < cumulative + length:
            return page.pdf_page
        cumulative += length
    return doc.pages[-1].pdf_page if doc.pages else 1


def parse_etsi_crosswalk(doc: ParsedDocument) -> list[EtsiClauseCrosswalk]:
    full = doc.full_cleaned_text
    crosswalks: list[EtsiClauseCrosswalk] = []

    # Find section 5 clause blocks
    section5_match = re.search(r"5\s+Technical requirements for products\s*(.*?)\n6\s+", full, re.S)
    if not section5_match:
        return crosswalks

    section5 = section5_match.group(1)
    clause_starts = list(_CLAUSE_HEADER_RE.finditer(section5))

    for i, header in enumerate(clause_starts):
        if not header.group(1).startswith("5."):
            continue
        start = header.end()
        end = clause_starts[i + 1].start() if i + 1 < len(clause_starts) else len(section5)
        block = section5[start:end]

        addr = _CRA_ADDRESS_RE.search(block)
        if not addr:
            continue

        cra_part = addr.group(1).upper()
        cra_parent = addr.group(2)
        cra_point = addr.group(3)

        requirements: list[EtsiRequirement] = []
        for rm in _REQ_ID_RE.finditer(block):
            req_id = rm.group(1)
            req_text = rm.group(2).strip()
            # Find applicability conditions after this requirement
            after = block[rm.end() :]
            conditions = [
                c.group(1).strip()
                for c in _APPLICABILITY_RE.finditer(after[:500])
            ]
            requirements.append(
                EtsiRequirement(
                    requirement_id=req_id,
                    text=req_text,
                    applicability_conditions=conditions,
                    pdf_page=_page_for_offset(doc, start + rm.start()),
                )
            )

        crosswalks.append(
            EtsiClauseCrosswalk(
                clause_number=header.group(1),
                clause_title=header.group(2).strip(),
                cra_annex="I",
                cra_part=cra_part,
                cra_point=f"{cra_parent}-{cra_point}" if cra_part == "I" and cra_parent == "2" else cra_point,
                requirements=requirements,
            )
        )

    # Parse section 6 assessment criteria IDs
    section6_match = re.search(r"6\s+Assessment criteria.*", full, re.S)
    if section6_match:
        assessment_ids = list(set(_ASSESSMENT_ID_RE.findall(section6_match.group(0))))
        for cw in crosswalks:
            prefix_map = {
                "5.2": "CYB_GENERAL",
                "5.3": "KEV_EXPLOIT",
                "5.4": "SBD",
                "5.5": "SU_UPDATES",
                "5.6": "AAC",
                "5.7": "CON",
                "5.8": "INT",
                "5.9": "DATA",
                "5.10": "AVAIL",
                "5.11": "NONINT",
                "5.12": "ASM",
                "5.13": "EXPLOIT",
                "5.14": "MON",
                "5.15": "RESET",
            }
            prefix = prefix_map.get(cw.clause_number[:3], cw.clause_number)
            cw.assessment_criteria_ids = [
                aid for aid in assessment_ids if aid.startswith(prefix.split("_")[0])
            ]

    return crosswalks


def cra_point_key(cra_part: str, cra_point: str) -> str:
    if cra_part == "I" and "-" in cra_point:
        parent, letter = cra_point.split("-", 1)
        return f"I-2-{letter}"
    if cra_part == "I":
        return f"I-{cra_point}"
    return f"II-{cra_point}"
