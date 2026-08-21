"""Deterministic composition of remediation items from an assessment.

The composer is a mapping, not an author. A technical recommendation is the
approved control's ``remediation_seed.recommendation`` copied verbatim; if the
registry has no approved guidance for a failing control, the item becomes a
human review request rather than an improvised fix. Nothing here produces a
shell command, a configuration snippet or an implementation step.

Finding context — observed state, the rules that did not match, evidence IDs —
is quoted from the Flow 3 result so the reader can see why the control failed
without the composer restating it in its own words.
"""

from __future__ import annotations

import json
from typing import Any

from src.assessment.models import Assessment, ControlResult, EvidenceGap, Verdict
from src.remediation.models import (
    CLEAR_VERDICTS,
    ActionType,
    RemediationItem,
    RemediationReasonCode,
    VerificationRequirement,
    make_remediation_id,
)

#: Collection statuses that mean the tool ran badly rather than never ran.
COLLECTION_ERROR_STATUSES = {
    "TOOL_UNAVAILABLE",
    "TARGET_UNREACHABLE",
    "PERMISSION_DENIED",
    "PARSE_ERROR",
}

#: Operators whose rule carries no comparison value.
VALUELESS_OPERATORS = {"EXISTS", "NOT_EXISTS"}

NO_APPROVED_GUIDANCE = (
    "The approved registry defines no remediation guidance for this control, so "
    "no recommendation can be issued. A reviewer must approve remediation "
    "guidance for the control before a fix is proposed."
)

HUMAN_DECISION = (
    "This control was not decided by the deterministic evaluator. A reviewer "
    "must make the decision; it must not be converted into a technical fix."
)


def _format_rule(rule: dict[str, Any]) -> str:
    """Render one unmatched condition as approved-rule text, not as a fix."""
    path = rule.get("path", "")
    operator = rule.get("operator", "")
    if operator in VALUELESS_OPERATORS:
        return f"{path} {operator}".strip()
    value = json.dumps(rule.get("value"), sort_keys=True, separators=(",", ":"))
    return f"{path} {operator} {value}".strip()


def _failed_rule_refs(result: ControlResult) -> list[str]:
    refs: list[str] = []
    for entry in result.evaluator_trace:
        if entry.matched:
            continue
        ref = _format_rule(entry.rule)
        if ref and ref not in refs:
            refs.append(ref)
    return refs


def _dedupe(values: list[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.append(value)
    return seen


def _gap_keys(gaps: list[EvidenceGap]) -> list[str]:
    return _dedupe([gap.evidence_key for gap in gaps])


def _gap_reason_code(gaps: list[EvidenceGap]) -> RemediationReasonCode:
    if any(gap.status in COLLECTION_ERROR_STATUSES for gap in gaps):
        return RemediationReasonCode.EVIDENCE_COLLECTION_ERROR
    return RemediationReasonCode.REQUIRED_EVIDENCE_NOT_COLLECTED


def _tools_for_keys(control: dict[str, Any], evidence_keys: list[str]) -> list[str]:
    """The MCP tools the approved evidence plan names for these keys."""
    by_key = {
        item.get("evidence_key"): item.get("mcp_tool")
        for item in control.get("evidence_plan", [])
    }
    return _dedupe([by_key.get(key) or "" for key in evidence_keys])


def _verification(
    control: dict[str, Any],
    *,
    registry_version: str,
    registry_hash: str,
    evidence_keys: list[str],
) -> VerificationRequirement:
    return VerificationRequirement(
        control_id=control.get("control_id", ""),
        registry_version=registry_version,
        registry_hash=registry_hash,
        evidence_keys=evidence_keys,
        mcp_tools=_tools_for_keys(control, evidence_keys),
    )


def _seed_recommendation(control: dict[str, Any]) -> str:
    seed = control.get("remediation_seed") or {}
    return (seed.get("recommendation") or "").strip()


def _seed_evidence_keys(control: dict[str, Any]) -> list[str]:
    seed = control.get("remediation_seed") or {}
    return _dedupe(list(seed.get("verification_evidence_keys") or []))


def action_type_for(verdict: Verdict, recommendation: str) -> ActionType | None:
    """The single rule mapping a verdict to an action type.

    Shared with verification so a finding's identifier is the same whether it is
    being composed or being checked for closure.
    """
    if verdict in CLEAR_VERDICTS:
        return None
    if verdict == Verdict.HUMAN_REVIEW_REQUIRED:
        return ActionType.HUMAN_REVIEW
    if verdict == Verdict.INSUFFICIENT_EVIDENCE:
        return ActionType.EVIDENCE_RESOLUTION
    return ActionType.TECHNICAL_REMEDIATION if recommendation else ActionType.HUMAN_REVIEW


def compose_item(
    result: ControlResult,
    control: dict[str, Any],
    *,
    assessment_id: str,
    run_id: str,
    target_id: str,
    registry_version: str,
    registry_hash: str,
) -> RemediationItem | None:
    """Map one assessed control to at most one advisory action."""
    recommendation = _seed_recommendation(control)
    action = action_type_for(result.verdict, recommendation)
    if action is None:
        return None

    common = {
        "remediation_id": make_remediation_id(assessment_id, result.control_id, action),
        "action_type": action,
        "assessment_id": assessment_id,
        "run_id": run_id,
        "target_id": target_id,
        "finding_control_id": result.control_id,
        "finding_title": result.title,
        "finding_verdict": result.verdict,
        "evidence_ids": list(result.evidence_ids),
        "observed_state": result.observed_state,
    }

    if result.verdict == Verdict.HUMAN_REVIEW_REQUIRED:
        return RemediationItem(
            reason=f"{HUMAN_DECISION} {result.reason}".strip(),
            reason_code=RemediationReasonCode.HUMAN_DECISION_REQUIRED,
            **common,
        )

    if result.verdict == Verdict.INSUFFICIENT_EVIDENCE:
        missing = _gap_keys(result.evidence_gaps)
        return RemediationItem(
            missing_evidence_keys=missing,
            reason=result.reason,
            reason_code=_gap_reason_code(result.evidence_gaps),
            verification=_verification(
                control,
                registry_version=registry_version,
                registry_hash=registry_hash,
                evidence_keys=missing or _seed_evidence_keys(control),
            ),
            **common,
        )

    # FAIL, and PARTIAL — which this evaluator only reaches through an approved
    # ``partial_when`` condition, so it is a verdict the control itself defines.
    if not recommendation:
        return RemediationItem(
            failed_rule_refs=_failed_rule_refs(result),
            reason=f"{NO_APPROVED_GUIDANCE} {result.reason}".strip(),
            reason_code=RemediationReasonCode.REMEDIATION_GUIDANCE_NOT_APPROVED,
            **common,
        )

    return RemediationItem(
        failed_rule_refs=_failed_rule_refs(result),
        recommendation=recommendation,
        reason=result.reason,
        verification=_verification(
            control,
            registry_version=registry_version,
            registry_hash=registry_hash,
            evidence_keys=_seed_evidence_keys(control),
        ),
        **common,
    )


def compose(assessment: Assessment, registry: dict[str, Any]) -> list[RemediationItem]:
    """Compose every advisory action for an assessment, in control order."""
    controls = {
        control.get("control_id"): control for control in registry.get("controls", [])
    }
    metadata = assessment.metadata
    items: list[RemediationItem] = []
    for result in assessment.results:
        item = compose_item(
            result,
            controls.get(result.control_id, {}),
            assessment_id=metadata.assessment_id,
            run_id=metadata.run_id,
            target_id=metadata.target_id,
            registry_version=metadata.registry_version,
            registry_hash=metadata.registry_hash,
        )
        if item is not None:
            items.append(item)
    return items
