"""Plain-language explanations for the vocabulary the artifacts use.

These power the "Why?" tooltips and the Settings glossary. The wording matches
what the application actually does, so a term never promises more than the
deterministic pipeline delivers.
"""

from __future__ import annotations

GLOSSARY: dict[str, str] = {
    # Verdicts
    "PASS": (
        "Every mandatory approved rule matched the collected evidence. This "
        "describes the observed configuration at collection time, not certification."
    ),
    "FAIL": (
        "At least one mandatory approved rule did not match the collected evidence."
    ),
    "PARTIAL": (
        "An explicit approved 'partial_when' condition was met. It never means "
        "'some rules passed'."
    ),
    "INSUFFICIENT_EVIDENCE": (
        "Required evidence was not successfully collected. This is not treated as "
        "a security failure."
    ),
    "HUMAN_REVIEW_REQUIRED": (
        "The approved control requires a product or human decision that cannot be "
        "resolved deterministically from the collected evidence."
    ),
    "NOT_APPLICABLE": (
        "The approved control declares this requirement does not apply to this product."
    ),
    # Evidence collection statuses
    "COLLECTED": "The tool returned a result that was normalized and stored.",
    "TOOL_UNAVAILABLE": (
        "The approved control names a capability this MCP build does not register."
    ),
    "TARGET_UNREACHABLE": "The target did not respond to the collection attempt.",
    "PERMISSION_DENIED": "The read-only account could not access the requested resource.",
    "PARSE_ERROR": "A result came back but could not be normalized into the evidence contract.",
    "NOT_COLLECTED": (
        "No call was attempted, usually because a parameter was unresolved or the "
        "evidence is documentary rather than technical."
    ),
    # Reason codes worth explaining in place
    "PARAMETER_UNRESOLVED": (
        "The approved control needs a value the product profile still marks "
        "<TO_BE_PROVIDED>. It fails closed rather than being guessed."
    ),
    "DOCUMENTARY_OR_HUMAN": (
        "This evidence is a document or a human statement, so no scan can produce it."
    ),
    # Applicability
    "APPLICABLE": "The approved control applies to this product without conditions.",
    "CONDITIONAL": (
        "Applicability depends on a product architecture fact that is not yet resolved."
    ),
    # Remediation actions
    "TECHNICAL_REMEDIATION": (
        "A failing control with approved remediation guidance. The recommendation is "
        "copied verbatim from the approved registry; nothing is executed."
    ),
    "EVIDENCE_RESOLUTION": (
        "Evidence was missing, so there is nothing to fix yet. Obtain the evidence "
        "and re-scan."
    ),
    "HUMAN_REVIEW": (
        "A decision a person must make. It is stated, never converted into an "
        "automated verdict."
    ),
    # Statuses
    "OPEN": "This finding has not been closed by a later evidence-backed assessment.",
    "VERIFIED_CLOSED": (
        "A later assessment returned PASS for this control, on the same target, under "
        "the same approved registry hash, backed by evidence that run actually collected."
    ),
    "STILL_OPEN": "The later assessment did not return PASS for this control.",
    "VERIFICATION_BLOCKED": (
        "The two assessments are not the same baseline, so nothing can be compared."
    ),
    "REGISTRY_BASELINE_CHANGED": (
        "The approved registry changed between the runs. A control may be reassessed "
        "under the new baseline, but that is not closure under the old one."
    ),
    "REVIEW": (
        "Human review is required. This is not a FAIL; submit evidence for analysis."
    ),
    "REMEDIATION_PENDING": (
        "A remediation action is in progress or applied but not yet verified by a "
        "fresh evidence-backed assessment. The finding remains OPEN."
    ),
    "PROPOSED": "A remediation action has been drafted from an eligible failed finding.",
    "AWAITING_APPROVAL": "The proposal is waiting for an explicit named approver.",
    "APPROVED": "An approver accepted the proposal; apply is allowed on the demo target.",
    "APPLYING": "Allow-listed demo execution has started.",
    "APPLIED_UNVERIFIED": (
        "The allow-listed change was applied on the demo target. The finding is still "
        "OPEN until a fresh re-scan returns PASS."
    ),
    "PENDING": "Remediation is recommended but not yet applied (legacy overlay).",
    "IN_PROGRESS": "Legacy overlay: execution had started.",
    "APPLIED": "Legacy overlay: applied before the action lifecycle split.",
    "VERIFYING": "Legacy overlay: in-process verification (no longer used for apply).",
    "VERIFIED": (
        "The remediation action was verified by a later evidence-backed PASS for the "
        "same control, target and approved registry baseline."
    ),
    "FAILED": "Remediation application or verification did not succeed; finding stays OPEN.",
    "ROLLED_BACK": "The demo overlay operation was rolled back; finding stays OPEN.",
    "BLOCKED": (
        "Execution or verification is blocked (for example non-demo target or "
        "registry baseline change)."
    ),
    # Modes and context
    "DETERMINISTIC": (
        "The verdict comes from the rule engine evaluating the approved rules. No "
        "model is involved."
    ),
    "HUMAN_OR_AGENT_REASONING": (
        "The approved control carries no deterministic rule, so it cannot be decided "
        "automatically."
    ),
    "TECHNICAL": "Evidence a read-only tool can collect from the target.",
    "DOCUMENTARY_OR_HUMAN_MODE": "Evidence that must come from a document or a person.",
    "MOCK": (
        "This run uses synthetic evidence and is not an assessment of a real target."
    ),
    "APPLICATION": (
        "A NetBoss-XT application in the target environment. Assessment and "
        "remediation are scoped to the selected application: Router Monitor, "
        "Switch Monitor, or SBC Monitor."
    ),
    "UNCLASSIFIED": (
        "The registry defines no approved severity model, so every finding carries "
        "this value."
    ),
    "DRAFT": (
        "A proposed registry. It cannot be scanned against until it is approved."
    ),
    "APPROVED": (
        "An immutable versioned baseline. Its content hash is checked before every scan."
    ),
}


def explain(term: str | None) -> str:
    """The explanation for a term, or an empty string when there is none."""
    if not term:
        return ""
    return GLOSSARY.get(str(term), "")
