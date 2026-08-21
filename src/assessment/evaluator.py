"""Deterministic rule engine.

The verdict for every control is produced here and nowhere else. The engine is
reproducible: the same approved registry and the same evidence always yield the
same verdict and the same trace.

Evidence is scoped to the control that requested it. A control never sees an
observation collected only for a different control, even when both used the
same MCP capability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from src.assessment.derive import derive_paths
from src.assessment.models import (
    ControlResult,
    DerivedPath,
    EvidenceGap,
    REMEDIATION_VERDICTS,
    RuleTraceEntry,
    Verdict,
)
from src.config import DEFAULT_SEVERITY
from src.evidence.models import CollectionStatus, EvidenceItem, EvidenceRun
from src.policy.assertions import SecurityAssertions
from src.rules.dsl import Operator

#: Applicability values that leave a human judgement unresolved.
UNRESOLVED_APPLICABILITY = {"CONDITIONAL", "HUMAN_REVIEW_REQUIRED"}

_MISSING = object()


class EvaluatorError(Exception):
    """The approved control cannot be executed by this implementation.

    Raised for unsupported operators, malformed rules and comparison errors.
    Never converted into PASS or FAIL.
    """


class PathUnresolved(Exception):
    """No collected evidence for this control can supply the rule path."""

    def __init__(self, path: str):
        super().__init__(f"No collected evidence provides '{path}'")
        self.path = path


@dataclass
class ControlEvidence:
    """The evidence one control may be evaluated against."""

    items: list[EvidenceItem] = field(default_factory=list)
    #: evidence_key -> the collection status recorded for it
    gaps: list[EvidenceGap] = field(default_factory=list)
    #: normalized namespaces augmented with derived paths, per evidence item
    augmented: dict[str, dict[str, Any]] = field(default_factory=dict)
    derived: list[DerivedPath] = field(default_factory=list)

    @property
    def evidence_ids(self) -> list[str]:
        return [item.evidence_id for item in self.items]


def collect_control_evidence(
    control: dict[str, Any], run: EvidenceRun, policy: SecurityAssertions
) -> ControlEvidence:
    """Gather the evidence associated with one control, and derive its paths."""
    control_id = control.get("control_id", "")
    required_by_key = {
        item.get("evidence_key", ""): bool(item.get("required", True))
        for item in control.get("evidence_plan", [])
    }

    scoped = ControlEvidence()
    for item in run.evidence:
        keys = [r.evidence_key for r in item.requested_by if r.control_id == control_id]
        if not keys:
            continue
        scoped.items.append(item)

        if item.status is not CollectionStatus.COLLECTED or not item.normalized:
            for key in keys:
                scoped.gaps.append(
                    EvidenceGap(
                        evidence_key=key,
                        status=item.status.value,
                        reason_code=(
                            item.status_reason_code.value if item.status_reason_code else None
                        ),
                        required=required_by_key.get(key, True),
                    )
                )
            continue

        augmented, derived = derive_paths(item.normalized, policy)
        scoped.augmented[item.evidence_id] = augmented
        for path, basis in derived:
            scoped.derived.append(
                DerivedPath(path=path, evidence_id=item.evidence_id, basis=basis)
            )

    return scoped


def _resolve(namespace: dict[str, Any], segments: list[str]) -> Any:
    current: Any = namespace
    for segment in segments:
        if not isinstance(current, dict) or segment not in current:
            return _MISSING
        current = current[segment]
    return current


def _observations(path: str, scoped: ControlEvidence) -> list[tuple[str, Any]]:
    """Every ``(evidence_id, value)`` this control offers for ``path``.

    A control may legitimately hold several evidence items under one namespace
    root, for example TLS on both port 443 and port 8443. All of them are
    returned so the condition can be required to hold for each.
    """
    segments = path.split(".")
    if not segments or not segments[0]:
        raise EvaluatorError(f"Invalid rule path: {path!r}")

    root = segments[0]
    found: list[tuple[str, Any]] = []
    for evidence_id, namespace in sorted(scoped.augmented.items()):
        if root not in namespace:
            continue
        value = _resolve(namespace, segments)
        found.append((evidence_id, None if value is _MISSING else value))

    if not found:
        raise PathUnresolved(path)
    return found


def _contains(observed: Any, needle: Any) -> bool:
    if observed is None:
        return False
    if isinstance(observed, str):
        return str(needle).lower() in observed.lower()
    if isinstance(observed, (list, tuple, set)):
        for element in observed:
            if element == needle:
                return True
            if isinstance(element, str) and str(needle).lower() in element.lower():
                return True
        return False
    if isinstance(observed, dict):
        return needle in observed
    return observed == needle


def apply_operator(operator: Operator, observed: Any, expected: Any) -> bool:
    """Evaluate one condition. Unsupported input raises rather than guessing."""
    if operator is Operator.EXISTS:
        return observed is not None
    if operator is Operator.NOT_EXISTS:
        return observed is None
    if operator is Operator.EQ:
        return observed == expected
    if operator is Operator.NE:
        return observed != expected
    if operator is Operator.IN:
        if not isinstance(expected, (list, tuple, set)):
            raise EvaluatorError(f"IN requires a list value, got {type(expected).__name__}")
        return observed in expected
    if operator is Operator.NOT_IN:
        if not isinstance(expected, (list, tuple, set)):
            raise EvaluatorError(f"NOT_IN requires a list value, got {type(expected).__name__}")
        return observed not in expected
    if operator is Operator.CONTAINS:
        return _contains(observed, expected)
    if operator is Operator.NOT_CONTAINS:
        return not _contains(observed, expected)
    if operator in (Operator.GTE, Operator.LTE):
        if not isinstance(observed, (int, float)) or isinstance(observed, bool):
            raise EvaluatorError(f"{operator.value} requires a numeric observation")
        if not isinstance(expected, (int, float)) or isinstance(expected, bool):
            raise EvaluatorError(f"{operator.value} requires a numeric value")
        return observed >= expected if operator is Operator.GTE else observed <= expected
    if operator is Operator.MATCHES:
        try:
            return re.search(str(expected), "" if observed is None else str(observed)) is not None
        except re.error as exc:
            raise EvaluatorError(f"Invalid MATCHES pattern {expected!r}: {exc}") from exc
    raise EvaluatorError(f"Unsupported operator: {operator!r}")


def _evaluate_condition(
    condition: dict[str, Any], scoped: ControlEvidence, trace: list[RuleTraceEntry]
) -> bool:
    path = condition.get("path")
    raw_operator = condition.get("operator")
    expected = condition.get("value")

    if not isinstance(path, str):
        raise EvaluatorError(f"Rule condition has no usable path: {condition!r}")
    try:
        operator = Operator(raw_operator)
    except ValueError as exc:
        raise EvaluatorError(f"Unsupported operator {raw_operator!r} on path {path}") from exc

    observations = _observations(path, scoped)
    results = [
        (evidence_id, value, apply_operator(operator, value, expected))
        for evidence_id, value in observations
    ]
    matched = all(outcome for _, _, outcome in results)

    values = [value for _, value, _ in results]
    trace.append(
        RuleTraceEntry(
            rule={"path": path, "operator": operator.value, "value": expected},
            observed=values[0] if len(values) == 1 else values,
            matched=matched,
            evidence_ids=[evidence_id for evidence_id, _, _ in results],
            note=(
                None
                if len(results) == 1
                else f"condition must hold for all {len(results)} associated evidence items"
            ),
        )
    )
    return matched


def evaluate_expression(
    expression: dict[str, Any], scoped: ControlEvidence, trace: list[RuleTraceEntry]
) -> bool:
    """Evaluate one rule expression, recording each condition in ``trace``."""
    if not isinstance(expression, dict):
        raise EvaluatorError(f"Rule expression must be an object: {expression!r}")

    if "all" in expression:
        branches = expression["all"]
        if not isinstance(branches, list):
            raise EvaluatorError("'all' must contain a list of expressions")
        # Evaluated in full rather than short-circuited so the trace shows
        # every condition a reviewer would expect to see.
        return all([evaluate_expression(branch, scoped, trace) for branch in branches])

    if "any" in expression:
        branches = expression["any"]
        if not isinstance(branches, list):
            raise EvaluatorError("'any' must contain a list of expressions")
        return any([evaluate_expression(branch, scoped, trace) for branch in branches])

    return _evaluate_condition(expression, scoped, trace)


def _evaluate_rules(
    rules: list[Any], scoped: ControlEvidence, trace: list[RuleTraceEntry]
) -> bool:
    """A control's top-level rule list is an implicit AND across its entries."""
    return all([evaluate_expression(rule, scoped, trace) for rule in rules])


def evaluate_control(
    control: dict[str, Any], run: EvidenceRun, policy: SecurityAssertions
) -> ControlResult:
    """Produce the authoritative verdict and trace for one approved control.

    Precedence, applied in order:

    1. approved applicability NOT_APPLICABLE
    2. unresolved applicability, or a control that is not deterministic
    3. required technical evidence missing or not collected
    4. an evaluator error this implementation cannot execute
    5. deterministic evaluation, with PARTIAL only where the approved control
       defines ``partial_when``
    """
    evaluation = control.get("evaluation") or {}
    mode = evaluation.get("mode", "UNKNOWN")
    rules = evaluation.get("rules") or []
    applicability = control.get("applicability") or {}
    status = applicability.get("status")

    scoped = collect_control_evidence(control, run, policy)
    result = ControlResult(
        control_id=control.get("control_id", ""),
        title=control.get("title", ""),
        source_traceability=control.get("source_traceability") or {},
        verdict=Verdict.HUMAN_REVIEW_REQUIRED,
        evaluation_mode=mode,
        evidence_ids=scoped.evidence_ids,
        evidence_gaps=scoped.gaps,
        derived_paths=scoped.derived,
        severity=DEFAULT_SEVERITY,
        remediation_seed=control.get("remediation_seed") or {},
        legal_requirement=control.get("legal_requirement") or {},
        nms_interpretation=control.get("nms_interpretation", ""),
        technical_control=control.get("technical_control", ""),
        applicability=applicability,
        registry_human_review_flag=bool(control.get("human_review_required")),
    )

    if status == "NOT_APPLICABLE":
        result.verdict = Verdict.NOT_APPLICABLE
        return result

    if status in UNRESOLVED_APPLICABILITY or mode != "DETERMINISTIC" or not rules:
        result.verdict = Verdict.HUMAN_REVIEW_REQUIRED
        return result

    trace: list[RuleTraceEntry] = []
    try:
        matched = _evaluate_rules(rules, scoped, trace)
    except PathUnresolved as exc:
        result.evaluator_trace = trace
        result.verdict = Verdict.INSUFFICIENT_EVIDENCE
        result.evaluator_error = str(exc)
        return result
    except EvaluatorError as exc:
        result.evaluator_trace = trace
        result.verdict = Verdict.HUMAN_REVIEW_REQUIRED
        result.evaluator_error = str(exc)
        return result

    result.evaluator_trace = trace
    if matched:
        result.verdict = Verdict.PASS
    else:
        result.verdict = _failed_verdict(evaluation, scoped, result)

    result.remediation_required = result.verdict in REMEDIATION_VERDICTS
    return result


def _failed_verdict(
    evaluation: dict[str, Any], scoped: ControlEvidence, result: ControlResult
) -> Verdict:
    """FAIL unless the approved control explicitly defines a partial condition.

    PARTIAL never means "some rules passed". It is only reachable through an
    approved ``partial_when`` expression, which no control defines today.
    """
    partial_when = evaluation.get("partial_when")
    if not partial_when:
        return Verdict.FAIL

    partial_trace: list[RuleTraceEntry] = []
    try:
        if evaluate_expression(partial_when, scoped, partial_trace):
            result.evaluator_trace.extend(partial_trace)
            return Verdict.PARTIAL
    except (EvaluatorError, PathUnresolved) as exc:
        result.evaluator_error = f"partial_when could not be evaluated: {exc}"
    return Verdict.FAIL


def evaluate_all(
    registry: dict[str, Any], run: EvidenceRun, policy: SecurityAssertions
) -> list[ControlResult]:
    return [evaluate_control(c, run, policy) for c in registry.get("controls", [])]
