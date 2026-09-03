"""In-run lifecycle overlay: remediation-action execution and human evidence review.

Does not mutate Flow 3 assessment.json verdicts. Flow 4 finding status is updated
only by reconcile after evidence-backed verification.
"""

from src.lifecycle.analyzer import (
    EvidenceAnalyzer,
    MockEvidenceAnalyzer,
    get_evidence_analyzer,
    set_evidence_analyzer,
)
from src.lifecycle.executor import (
    AllowlistedDemoExecutor,
    MockRemediationExecutor,
    RemediationExecutor,
    get_remediation_executor,
    set_remediation_executor,
)
from src.lifecycle.models import (
    ACTION_LIFECYCLE_STATUSES,
    AnalysisDecision,
    ApprovalAction,
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
    apply_action,
    apply_remediation,
    approve_action,
    propose_action,
    reconcile_actions_from_verification,
    refresh_reports,
    rollback_action,
)
from src.lifecycle.store import load_lifecycle, save_lifecycle

__all__ = [
    "ACTION_LIFECYCLE_STATUSES",
    "AllowlistedDemoExecutor",
    "AnalysisDecision",
    "ApprovalAction",
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
    "apply_action",
    "apply_remediation",
    "approve_action",
    "get_evidence_analyzer",
    "get_remediation_executor",
    "load_lifecycle",
    "propose_action",
    "reconcile_actions_from_verification",
    "refresh_reports",
    "rollback_action",
    "save_lifecycle",
    "set_evidence_analyzer",
    "set_remediation_executor",
]
