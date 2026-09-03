"""Normalized compliance view for UI and reports.

This package projects Flow 2–4 artifacts into a stable presentation model.
It does not decide verdicts, invent evidence, or replace the MCP / evaluator
engines. A later Ollama provider can populate the same structures.
"""

from src.compliance.models import (
    AssessmentSummaryView,
    AssessmentView,
    Asset,
    AssetType,
    ControlView,
    DisplaySeverity,
    EvidenceFact,
    FindingView,
    OverallStatus,
    RemediationView,
    ReviewHistoryEntry,
    UIStatus,
)
from src.compliance.provider import ComplianceProvider, get_compliance_provider
from src.compliance.status import map_verdict, overall_status

__all__ = [
    "AssessmentSummaryView",
    "AssessmentView",
    "Asset",
    "AssetType",
    "ComplianceProvider",
    "ControlView",
    "DisplaySeverity",
    "EvidenceFact",
    "FindingView",
    "OverallStatus",
    "RemediationView",
    "ReviewHistoryEntry",
    "UIStatus",
    "get_compliance_provider",
    "map_verdict",
    "overall_status",
]
