"""ComplianceProvider boundary for MOCK now and Ollama later.

Both providers must return the same ``AssessmentView`` structures so the UI
and reports do not depend on provider-specific shapes. This phase implements
only ``MockComplianceProvider``.

A future ``OllamaComplianceProvider`` may fill whitelisted short fields
(requirement, finding, recommendedAction, verification, applicability hints)
from deterministic inputs. It must not set verdict, status, hashes, evidence
IDs, or invent observations that the evidence run did not collect.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from src.compliance.models import AssessmentView


@runtime_checkable
class ComplianceProvider(Protocol):
    """Load a normalized compliance view for one assessment run."""

    def load(self, run_id: str) -> AssessmentView:
        """Return an AssessmentView for ``run_id``.

        Implementations must not invent evidence. Missing artifacts yield an
        empty or partial view rather than fabricated findings.
        """
        ...


class ComplianceProviderBase(ABC):
    """Optional base for concrete providers."""

    @abstractmethod
    def load(self, run_id: str) -> AssessmentView:
        ...


_default_provider: ComplianceProvider | None = None


def get_compliance_provider() -> ComplianceProvider:
    """Return the active compliance provider (MOCK in this phase)."""
    global _default_provider
    if _default_provider is None:
        from src.compliance.mock_provider import MockComplianceProvider

        _default_provider = MockComplianceProvider()
    return _default_provider


def set_compliance_provider(provider: ComplianceProvider | None) -> None:
    """Override the active provider (tests). Pass None to reset."""
    global _default_provider
    _default_provider = provider
