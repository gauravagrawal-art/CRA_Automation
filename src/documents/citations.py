"""Citation validation — verbatim substring and locator resolution."""

from __future__ import annotations

import re
from dataclasses import dataclass

from src.documents.parser import ParsedDocument
from src.documents.structure import StructureIndex


@dataclass
class CitationValidationResult:
    valid: bool
    errors: list[str]
    warnings: list[str]


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def validate_excerpt(
    excerpt: str,
    doc: ParsedDocument,
    *,
    pdf_page: int | None,
) -> CitationValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    if not excerpt or not excerpt.strip():
        errors.append("source_excerpt is empty")
        return CitationValidationResult(valid=False, errors=errors, warnings=warnings)

    normalized_excerpt = normalize_whitespace(excerpt)

    if pdf_page is None:
        warnings.append("page is null — excerpt not page-validated")
        return CitationValidationResult(valid=True, errors=errors, warnings=warnings)

    page_text = doc.page_text(pdf_page)
    if page_text is None:
        errors.append(f"page {pdf_page} not found in document")
        return CitationValidationResult(valid=False, errors=errors, warnings=warnings)

    normalized_page = normalize_whitespace(page_text)
    if normalized_excerpt not in normalized_page:
        # Try full document as fallback with warning
        full = normalize_whitespace(doc.full_cleaned_text)
        if normalized_excerpt not in full:
            errors.append(
                f"source_excerpt not found as verbatim substring on page {pdf_page} "
                f"or in full document"
            )
        else:
            warnings.append(
                f"excerpt found in document but not on declared page {pdf_page}"
            )

    return CitationValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )


def validate_locator(
    index: StructureIndex,
    *,
    page: int | None,
    article: str | None = None,
    annex: str | None = None,
    part: str | None = None,
    section: str | None = None,
    paragraph: str | None = None,
    clause: str | None = None,
) -> CitationValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    if page is None and not any([article, annex, part, section, paragraph, clause]):
        warnings.append("all locator fields are null — flagged for human review")
        return CitationValidationResult(valid=True, errors=errors, warnings=warnings)

    node = index.resolve_locator(
        page=page,
        article=article,
        annex=annex,
        part=part,
        section=section,
        paragraph=paragraph,
        clause=clause,
    )
    if node is None and page is not None:
        warnings.append(f"locator could not be resolved on page {page}")

    return CitationValidationResult(valid=True, errors=errors, warnings=warnings)


def validate_citation(
    excerpt: str,
    doc: ParsedDocument,
    index: StructureIndex,
    locator: dict,
) -> CitationValidationResult:
    excerpt_result = validate_excerpt(
        excerpt,
        doc,
        pdf_page=locator.get("page"),
    )
    locator_result = validate_locator(
        index,
        page=locator.get("page"),
        article=locator.get("article"),
        annex=locator.get("annex"),
        part=locator.get("part"),
        section=locator.get("section"),
        paragraph=locator.get("paragraph"),
        clause=locator.get("clause"),
    )
    return CitationValidationResult(
        valid=excerpt_result.valid and locator_result.valid,
        errors=excerpt_result.errors + locator_result.errors,
        warnings=excerpt_result.warnings + locator_result.warnings,
    )
