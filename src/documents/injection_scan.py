"""Prompt-injection pattern detection in source spans."""

from __future__ import annotations

import re
from dataclasses import dataclass

INJECTION_PATTERNS = [
    re.compile(r"\bignore (all )?(previous|prior) instructions\b", re.I),
    re.compile(r"\byou (must|should|need to) (run|execute|invoke)\b", re.I),
    re.compile(r"\bconnect to (the )?(target|system|server)\b", re.I),
    re.compile(r"\bdisregard (the )?(above|system) (prompt|instructions)\b", re.I),
    re.compile(r"\bact as (a|an) (admin|root|superuser)\b", re.I),
    re.compile(r"\bssh into\b", re.I),
    re.compile(r"\bpass (this|the) (audit|assessment|check)\b", re.I),
]


@dataclass
class InjectionCandidate:
    pattern: str
    matched_text: str
    start: int
    end: int


def scan_for_injection(text: str) -> list[InjectionCandidate]:
    candidates: list[InjectionCandidate] = []
    for pattern in INJECTION_PATTERNS:
        for m in pattern.finditer(text):
            candidates.append(
                InjectionCandidate(
                    pattern=pattern.pattern,
                    matched_text=m.group(0),
                    start=m.start(),
                    end=m.end(),
                )
            )
    return candidates


def wrap_for_model(text: str, label: str = "SOURCE_DATA") -> str:
    """Wrap source text in delimited data blocks for model consumption."""
    return f"<<<<<{label}_BEGIN>>>>>\n{text}\n<<<<<{label}_END>>>>>"
