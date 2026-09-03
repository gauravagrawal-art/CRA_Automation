"""Flow 3 orchestrator: preflight, evaluate, narrate, render.

The order matters. Verdicts exist before narration is attempted, so narration
can only ever change prose. The assessment completes whether or not a model is
configured and whether or not it succeeds.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from src.assessment.evaluator import evaluate_all
from src.assessment.models import (
    Assessment,
    AssessmentMetadata,
    ControlResult,
    HumanReviewItem,
    Limitation,
    LimitationCode,
    Verdict,
    summarize,
)
from src.assessment.narrative import narrate
from src.assessment.preflight import PreflightError, PreflightResult, preflight
from src.assessment.report import render_html
from src.config import ASSESSMENTS_DIR, EVIDENCE_DIR
from src.evidence.io import atomic_write_text, write_json_artifact
from src.llm.agent2 import Agent2Provider, load_agent2_prompt
from src.policy.assertions import load_security_assertions
from src.registry.approval import compute_hash

__all__ = ["assess", "PreflightError"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_assessment_id(registry_hash: str, evidence_sha256: str, generated_at: str) -> str:
    digest = compute_hash(
        {
            "registry_hash": registry_hash,
            "evidence_sha256": evidence_sha256,
            "generated_at": generated_at,
        }
    )
    return f"ASSESS-{digest[:12]}"


def _human_review_items(results: list[ControlResult]) -> list[HumanReviewItem]:
    return [
        HumanReviewItem(
            control_id=result.control_id,
            title=result.title,
            verdict=result.verdict,
            reason=result.reason,
        )
        for result in results
        if result.verdict in (Verdict.HUMAN_REVIEW_REQUIRED, Verdict.INSUFFICIENT_EVIDENCE)
    ]


def _limitations(
    results: list[ControlResult],
    pre: PreflightResult,
    unexplained: list[str],
    llm_enabled: bool,
) -> list[Limitation]:
    limitations: list[Limitation] = [
        Limitation(
            code=LimitationCode.NO_APPROVED_SEVERITY_MODEL,
            detail=(
                "The approved registry defines no severity or risk model, so every finding "
                "is recorded as UNCLASSIFIED. Severity is never inferred."
            ),
        )
    ]

    non_deterministic = [
        r.control_id for r in results if r.verdict is Verdict.HUMAN_REVIEW_REQUIRED
    ]
    if non_deterministic:
        limitations.append(
            Limitation(
                code=LimitationCode.NON_DETERMINISTIC_CONTROLS,
                detail=(
                    "These controls rest on documentary evidence or an unresolved "
                    "applicability decision. No automated verdict was generated for them."
                ),
                control_ids=non_deterministic,
            )
        )

    with_gaps = [r.control_id for r in results if r.evidence_gaps]
    if with_gaps:
        limitations.append(
            Limitation(
                code=LimitationCode.EVIDENCE_GAP,
                detail=(
                    "Approved evidence requests for these controls were not collected, so the "
                    "assessment is narrower than the approved evidence plan. Where a rule "
                    "needed the missing observation the verdict is INSUFFICIENT_EVIDENCE."
                ),
                control_ids=with_gaps,
            )
        )

    evaluator_errors = [
        r.control_id
        for r in results
        if r.evaluator_error and r.verdict is Verdict.HUMAN_REVIEW_REQUIRED
    ]
    if evaluator_errors:
        limitations.append(
            Limitation(
                code=LimitationCode.EVALUATOR_ERROR,
                detail=(
                    "The approved control could not be executed by this evaluator. Such "
                    "controls are routed to human review, never resolved as PASS or FAIL."
                ),
                control_ids=evaluator_errors,
            )
        )

    if pre.unknown_associations:
        pairs = ", ".join(f"{cid}/{key}" for cid, key in pre.unknown_associations)
        limitations.append(
            Limitation(
                code=LimitationCode.EVIDENCE_ASSOCIATION_UNKNOWN,
                detail=(
                    "Evidence declared an association with a control or evidence key absent "
                    f"from the approved registry; it was ignored: {pairs}"
                ),
                control_ids=sorted({cid for cid, _ in pre.unknown_associations}),
            )
        )

    if llm_enabled and unexplained:
        limitations.append(
            Limitation(
                code=LimitationCode.LLM_NARRATIVE_UNAVAILABLE,
                detail=(
                    "Agent 2 narration was enabled but produced no usable explanation for "
                    "these controls. Deterministic template explanations are shown instead; "
                    "verdicts are unaffected."
                ),
                control_ids=unexplained,
            )
        )

    return limitations


def build_assessment(
    pre: PreflightResult,
    *,
    provider: Agent2Provider | None = None,
    clock: Callable[[], str] | None = None,
) -> Assessment:
    """Evaluate and narrate, returning the assessment document in memory."""
    now = clock or _utc_now
    policy, _ = load_security_assertions()

    results = evaluate_all(pre.registry, pre.run, policy)

    system_prompt = ""
    if provider is not None:
        try:
            system_prompt = load_agent2_prompt()
        except OSError:
            system_prompt = ""
    unexplained = narrate(results, provider=provider, system_prompt=system_prompt)

    generated_at = now()
    metadata = AssessmentMetadata(
        assessment_id=make_assessment_id(
            pre.registry_hash, pre.evidence_sha256, generated_at
        ),
        run_id=pre.run.run.run_id,
        target_id=pre.run.run.target_id,
        registry_version=pre.registry.get("metadata", {}).get("registry_version", ""),
        registry_hash=pre.registry_hash,
        evidence_sha256=pre.evidence_sha256,
        provider=pre.run.run.provider,
        generated_at=generated_at,
        llm_narration="enabled" if provider is not None else "disabled",
        application_id=pre.run.run.application_id,
    )

    return Assessment(
        metadata=metadata,
        summary=summarize(results),
        results=results,
        limitations=_limitations(results, pre, unexplained, provider is not None),
        human_review_items=_human_review_items(results),
    )


def assess(
    *,
    run_id: str,
    registry_path: Path,
    evidence_dir: Path | None = None,
    output_dir: Path | None = None,
    provider: Agent2Provider | None = None,
    expected_target_id: str | None = None,
    clock: Callable[[], str] | None = None,
) -> tuple[Path, Assessment]:
    """Assess one evidence run and write ``assessment.json`` and ``assessment.html``.

    Returns ``(output_directory, assessment)``. Inputs are never modified.
    """
    evidence_path = (evidence_dir or EVIDENCE_DIR) / run_id / "evidence.json"
    pre = preflight(
        registry_path=registry_path,
        evidence_path=evidence_path,
        expected_target_id=expected_target_id,
    )

    assessment = build_assessment(pre, provider=provider, clock=clock)

    out_dir = (output_dir or ASSESSMENTS_DIR) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    document: dict[str, Any] = assessment.model_dump(mode="json", by_alias=True)
    write_json_artifact(out_dir / "assessment.json", document)
    atomic_write_text(out_dir / "assessment.html", render_html(assessment))
    return out_dir, assessment
