"""EvidenceAnalyzer boundary — MOCK now, Ollama later.

Analysers must return structured AnalysisDecision values. Free-form model
prose must never become a control status directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from src.lifecycle.models import (
    AnalysisDecision,
    EvidenceAnalysis,
    EvidenceSubmission,
)


@runtime_checkable
class EvidenceAnalyzer(Protocol):
    def analyse(
        self,
        *,
        requirement: str,
        asset_name: str,
        asset_type: str,
        control_id: str,
        submissions: list[EvidenceSubmission],
        clock: str,
    ) -> EvidenceAnalysis:
        ...


class EvidenceAnalyzerBase(ABC):
    @abstractmethod
    def analyse(
        self,
        *,
        requirement: str,
        asset_name: str,
        asset_type: str,
        control_id: str,
        submissions: list[EvidenceSubmission],
        clock: str,
    ) -> EvidenceAnalysis:
        ...


# Documented demo phrases (case-insensitive substring match).
_PASS_PHRASES = (
    "default admin account has been disabled",
    "default administrator account has been disabled",
    "default administrative account has been disabled",
    "default admin account disabled",
    "administrator account is disabled",
    "default account has been disabled",
)

_WEAK_PHRASES = (
    "password policy was reviewed",
    "password configuration reviewed",
    "policy was reviewed",
    "reviewed the configuration",
)


class MockEvidenceAnalyzer:
    """Deterministic fail-closed analyser for the demo.

    Future ``OllamaEvidenceAnalyzer`` (qwen3:8b) must return the same schema.
    """

    def analyse(
        self,
        *,
        requirement: str,
        asset_name: str,
        asset_type: str,
        control_id: str,
        submissions: list[EvidenceSubmission],
        clock: str,
    ) -> EvidenceAnalysis:
        latest = submissions[-1] if submissions else None
        description = (latest.description or "").strip() if latest else ""
        has_files = bool(latest and latest.attachments)

        if not description and not has_files:
            decision = AnalysisDecision.INSUFFICIENT_EVIDENCE
            reason = "No configuration or verification evidence was supplied."
            summary = "No evidence submitted."
            confidence = 0.95
        elif any(p in description.lower() for p in _PASS_PHRASES):
            decision = AnalysisDecision.PASS
            reason = (
                "Evidence confirms that the default administrative account is disabled."
            )
            summary = description
            confidence = 0.9
        elif any(p in description.lower() for p in _WEAK_PHRASES):
            decision = AnalysisDecision.FAIL
            reason = (
                "The submitted evidence does not demonstrate that the default "
                "administrative account is disabled."
            )
            summary = description
            confidence = 0.85
        else:
            decision = AnalysisDecision.FAIL
            reason = (
                "The submitted evidence does not demonstrate that the required "
                "configuration is in place."
            )
            summary = description or "(attachment only)"
            confidence = 0.7

        return EvidenceAnalysis(
            decision=decision,
            reason=reason,
            confidence=confidence,
            evidence_summary=summary,
            ai_decision=decision,
            human_decision=None,
            final_decision=decision,
            override_reason="",
            analysed_at=clock,
        )


_default_analyzer: EvidenceAnalyzer | None = None


def get_evidence_analyzer() -> EvidenceAnalyzer:
    global _default_analyzer
    if _default_analyzer is None:
        _default_analyzer = MockEvidenceAnalyzer()
    return _default_analyzer


def set_evidence_analyzer(analyzer: EvidenceAnalyzer | None) -> None:
    global _default_analyzer
    _default_analyzer = analyzer
