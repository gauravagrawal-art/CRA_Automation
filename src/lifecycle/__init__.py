"""In-run lifecycle overlay: mock remediation execution and human evidence review.

Does not mutate Flow 3 assessment.json or Flow 4 remediation.json. Providers
project overlay state into AssessmentView for the UI and concise reports.
"""

from src.lifecycle.analyzer import (
    EvidenceAnalyzer,
    MockEvidenceAnalyzer,
    get_evidence_analyzer,
    set_evidence_analyzer,
)
from src.lifecycle.executor import (
    MockRemediationExecutor,
    RemediationExecutor,
    get_remediation_executor,
    set_remediation_executor,
)
from src.lifecycle.models import (
    AnalysisDecision,
    ControlLifecycle,
    EvidenceAnalysis,
    EvidenceSource,
    EvidenceSubmission,
    LifecycleDocument,
    LifecycleStatus,
    RemediationExecStatus,
    RemediationOrigin,
    RemediationRecord,
)
from src.lifecycle.service import (
    LifecycleError,
    analyse_evidence,
    apply_remediation,
    refresh_reports,
)
from src.lifecycle.store import load_lifecycle, save_lifecycle

__all__ = [
    "AnalysisDecision",
    "ControlLifecycle",
    "EvidenceAnalysis",
    "EvidenceAnalyzer",
    "EvidenceSource",
    "EvidenceSubmission",
    "LifecycleDocument",
    "LifecycleError",
    "LifecycleStatus",
    "MockEvidenceAnalyzer",
    "MockRemediationExecutor",
    "RemediationExecStatus",
    "RemediationExecutor",
    "RemediationOrigin",
    "RemediationRecord",
    "analyse_evidence",
    "apply_remediation",
    "get_evidence_analyzer",
    "get_remediation_executor",
    "load_lifecycle",
    "refresh_reports",
    "save_lifecycle",
    "set_evidence_analyzer",
    "set_remediation_executor",
]
