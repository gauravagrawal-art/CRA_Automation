"""Explanations for verdicts the rule engine already decided.

Template narration is the baseline and is always available. Agent 2, when
enabled, replaces the prose only. The merge is a whitelist: three string fields
are copied across and everything else a provider returns is discarded, so the
verdict cannot be argued with.
"""

from __future__ import annotations

import json
from typing import Any

from src.assessment.models import ControlResult, RuleTraceEntry, Verdict
from src.llm.agent2 import Agent2Provider, NARRATIVE_FIELDS

#: Longest prose field accepted from a provider, per field.
MAX_NARRATIVE_CHARS = 2000

#: Longest serialization of one observed value sent to a provider or rendered
#: into a template sentence.
MAX_OBSERVED_CHARS = 240


def _short(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    if len(text) > MAX_OBSERVED_CHARS:
        return text[:MAX_OBSERVED_CHARS] + "..."
    return text


def _condition_sentence(entry: RuleTraceEntry) -> str:
    rule = entry.rule
    operator = rule.get("operator", "")
    path = rule.get("path", "")
    if operator in ("EXISTS", "NOT_EXISTS"):
        return f"{path} {operator}"
    return f"{path} {operator} {_short(rule.get('value'))}"


def _evidence_phrase(evidence_ids: list[str]) -> str:
    if not evidence_ids:
        return "no evidence"
    if len(evidence_ids) == 1:
        return evidence_ids[0]
    return ", ".join(evidence_ids)


def _observed_phrase(entry: RuleTraceEntry) -> str:
    """Render the observation, attributing each value to its evidence item."""
    ids = entry.evidence_ids
    if len(ids) > 1 and isinstance(entry.observed, list) and len(entry.observed) == len(ids):
        pairs = (f"{eid}={_short(value)}" for eid, value in zip(ids, entry.observed))
        return "; ".join(pairs)
    return f"{_short(entry.observed)} ({_evidence_phrase(ids)})"


def template_expected_state(result: ControlResult) -> str:
    if result.evaluator_trace:
        conditions = "; ".join(_condition_sentence(e) for e in result.evaluator_trace)
        return f"Approved deterministic conditions: {conditions}."
    if result.technical_control:
        return result.technical_control
    return "No deterministic condition is defined by the approved control."


def template_observed_state(result: ControlResult) -> str:
    if result.evaluator_trace:
        parts = [
            f"{entry.rule.get('path', '')} = {_observed_phrase(entry)}"
            for entry in result.evaluator_trace
        ]
        return "; ".join(parts) + "."
    if result.evidence_gaps:
        keys = ", ".join(gap.evidence_key for gap in result.evidence_gaps)
        return f"No deterministic observation was evaluated. Uncollected evidence: {keys}."
    return "No deterministic observation was evaluated for this control."


def _failed_conditions(result: ControlResult) -> list[RuleTraceEntry]:
    return [entry for entry in result.evaluator_trace if not entry.matched]


def template_reason(result: ControlResult) -> str:
    """Explain why the machine verdict follows, in one short sentence."""
    verdict = result.verdict

    if verdict is Verdict.NOT_APPLICABLE:
        approved_reason = result.applicability.get("reason") or "out of scope"
        return f"Not applicable: {approved_reason}"

    if verdict is Verdict.HUMAN_REVIEW_REQUIRED:
        return _human_review_reason(result)

    if verdict is Verdict.INSUFFICIENT_EVIDENCE:
        gaps = ", ".join(gap.evidence_key for gap in result.evidence_gaps[:3])
        if gaps:
            return f"Required evidence not collected: {gaps}."
        detail = result.evaluator_error or "required observation missing"
        return f"Insufficient evidence: {detail}."

    if verdict is Verdict.PASS:
        return "All approved conditions matched."

    failed = _failed_conditions(result)
    if not failed:
        return "Approved condition did not match."
    entry = failed[0]
    detail = (
        f"expected {_condition_sentence(entry)} but observed {_observed_phrase(entry)}"
    )
    if verdict is Verdict.PARTIAL:
        return f"Partial match: {detail}."
    return f"{detail}."


def _human_review_reason(result: ControlResult) -> str:
    if result.evaluator_error:
        return f"Evaluator could not run this control: {result.evaluator_error}."
    status = result.applicability.get("status")
    if status in ("CONDITIONAL", "HUMAN_REVIEW_REQUIRED"):
        approved_reason = result.applicability.get("reason") or "applicability unresolved"
        return f"Human review required ({status}): {approved_reason}."
    return "No deterministic rule; human judgement required."


def apply_template_narrative(result: ControlResult) -> ControlResult:
    """Fill the prose fields deterministically from the trace."""
    result.expected_state = template_expected_state(result)
    result.observed_state = template_observed_state(result)
    result.reason = template_reason(result)
    result.narrative_source = "template"
    return result


def build_payload(result: ControlResult) -> dict[str, Any]:
    """The minimal narrative payload for one control.

    Only normalized observations the trace actually referenced are included.
    Raw logs, raw configuration bodies and legal text are never sent.
    """
    return {
        "control_id": result.control_id,
        "title": result.title,
        "technical_control": result.technical_control,
        "machine_verdict": result.verdict.value,
        "evaluation_mode": result.evaluation_mode,
        "evaluator_trace": [
            {
                "rule": entry.rule,
                "observed": _short(entry.observed),
                "matched": entry.matched,
                "evidence_ids": entry.evidence_ids,
            }
            for entry in result.evaluator_trace
        ],
        "evidence_ids": result.evidence_ids,
        "evidence_gaps": [
            {"evidence_key": gap.evidence_key, "status": gap.status} for gap in result.evidence_gaps
        ],
        "remediation_seed": result.remediation_seed,
    }


def merge_narrative(result: ControlResult, response: Any) -> bool:
    """Copy accepted prose fields onto ``result``. Returns True if any applied.

    The verdict, severity, identifiers and trace are not readable from
    ``response``; only the three whitelisted strings are.
    """
    if not isinstance(response, dict):
        return False

    applied = False
    for field in NARRATIVE_FIELDS:
        value = response.get(field)
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text:
            continue
        setattr(result, field, text[:MAX_NARRATIVE_CHARS])
        applied = True

    if applied:
        result.narrative_source = "agent2"
    return applied


def narrate(
    results: list[ControlResult],
    *,
    provider: Agent2Provider | None = None,
    system_prompt: str = "",
) -> list[str]:
    """Narrate every result, returning the control IDs Agent 2 did not explain.

    Templates are applied first, so a provider that fails, returns nothing or
    returns garbage still leaves a complete, evidence-linked explanation.
    """
    for result in results:
        apply_template_narrative(result)

    if provider is None:
        return []

    unexplained: list[str] = []
    for result in results:
        try:
            response = provider.explain(
                system_prompt=system_prompt, payload=build_payload(result)
            )
        except Exception:
            unexplained.append(result.control_id)
            continue
        if not merge_narrative(result, response):
            unexplained.append(result.control_id)
    return unexplained
