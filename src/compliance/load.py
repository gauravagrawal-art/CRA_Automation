"""Thin helpers for loading a compliance view without UI-specific wiring."""

from __future__ import annotations

from src.compliance.models import AssessmentView
from src.compliance.provider import get_compliance_provider
from src.services import runs_service


def load_assessment_view(run_id: str | None = None) -> AssessmentView | None:
    """Load the normalized view for ``run_id``, or the latest assessed run."""
    if not run_id:
        runs = runs_service.list_runs()
        for run in runs:
            if run.has_assessment:
                run_id = run.run_id
                break
        if not run_id:
            return None
    return get_compliance_provider().load(run_id)
