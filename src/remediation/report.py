"""Deterministic HTML renderer for the Flow 4 final report.

The report is assembled from the stored assessment and remediation documents by
application templates. No model rebuilds a control ID, a verdict, a hash, an
evidence reference or a recommendation, and the assessment sections are the
same markup Flow 3 renders rather than a second copy of it.

Output is one self-contained file: inline styles, no scripts, no external
assets, reproducible from the JSON artifacts alone.
"""

from __future__ import annotations

from src.assessment.models import Assessment, Verdict
from src.assessment.report import (
    DISCLAIMER,
    STYLESHEET,
    escape_value as _e,
    render_control_table,
    render_details,
    render_field as _field,
    render_human_review,
    render_limitations,
    render_summary,
)
from src.remediation.models import (
    ActionType,
    RemediationDocument,
    RemediationItem,
    RemediationStatus,
    VerificationDocument,
    VerificationOutcome,
)

REPORT_TITLE = "NextBoss-XT CRA Technical Readiness Final Report"

ADVISORY_NOTICE = (
    "Remediation items in this report are advisory. They are composed from the "
    "approved control registry and the recorded assessment; this application "
    "changed nothing on the target, executes nothing, and generates no "
    "implementation commands. A finding closes only when a later evidence-backed "
    "assessment returns PASS under the same approved baseline."
)

MOCK_BANNER = "SYNTHETIC / MOCK ASSESSMENT DATA"

MOCK_BANNER_DETAIL = (
    "This report was produced from the mock evidence provider. The findings, "
    "observations and recommendations below describe synthetic fixture data. No "
    "real NextBoss-XT environment was assessed."
)

ACTION_LABELS = {
    ActionType.TECHNICAL_REMEDIATION: "Technical remediation",
    ActionType.EVIDENCE_RESOLUTION: "Evidence resolution",
    ActionType.HUMAN_REVIEW: "Human review",
}

OUTCOME_LABELS = {
    VerificationOutcome.VERIFIED_CLOSED: "Verified closed",
    VerificationOutcome.STILL_OPEN: "Still open",
    VerificationOutcome.VERIFICATION_BLOCKED: "Verification blocked",
}

EXTRA_STYLESHEET = """
.mockbanner {
  background: #7a1f1f; color: #fff; border-radius: 6px; padding: .9rem 1.1rem;
  margin: 0 0 1.5rem; text-align: center; letter-spacing: .1em; font-weight: 700;
}
.mockbanner .detail { display: block; margin-top: .4rem; font-weight: 400; letter-spacing: normal; font-size: .84rem; }
.advisory { background: #eaf2fa; border: 1px solid #a8c6e4; border-left: 5px solid var(--accent); border-radius: 6px; padding: .9rem 1.1rem; margin: 1rem 0 1.5rem; }
.advisory strong { display: block; margin-bottom: .25rem; text-transform: uppercase; font-size: .78rem; letter-spacing: .06em; }
.badge.TECHNICAL_REMEDIATION { background: var(--accent); }
.badge.EVIDENCE_RESOLUTION { background: var(--insufficient); }
.badge.HUMAN_REVIEW { background: var(--review); }
.badge.OPEN { background: var(--partial); }
.badge.VERIFIED_CLOSED { background: var(--pass); }
.badge.STILL_OPEN { background: var(--fail); }
.badge.VERIFICATION_BLOCKED { background: var(--insufficient); }
.tile.technical_remediation { border-top-color: var(--accent); }
.tile.evidence_resolution { border-top-color: var(--insufficient); }
.tile.human_review { border-top-color: var(--review); }
.tile.open { border-top-color: var(--partial); }
.tile.verified_closed { border-top-color: var(--pass); }
"""


def _mock_banner(assessment: Assessment) -> str:
    if assessment.metadata.provider != "mock":
        return ""
    return (
        f"<div class='mockbanner'>{_e(MOCK_BANNER)}"
        f"<span class='detail'>{_e(MOCK_BANNER_DETAIL)}</span></div>"
    )


def _header(assessment: Assessment, remediation: RemediationDocument) -> str:
    meta = remediation.metadata
    rows = [
        ("Target", meta.target_id),
        ("Scan / run ID", meta.run_id),
        ("Assessment ID", meta.assessment_id),
        ("Remediation ID", meta.remediation_run_id),
        ("Registry version", meta.registry_version),
        ("Registry hash", meta.registry_hash),
        ("Evidence SHA-256", meta.evidence_sha256),
        ("Assessment SHA-256", meta.assessment_sha256),
        ("Provider", meta.provider),
        ("LLM narration", assessment.metadata.llm_narration),
        ("Assessment generated", assessment.metadata.generated_at),
        ("Report generated", meta.generated_at),
    ]
    items = "".join(
        f"<dt>{_e(label)}</dt><dd class='mono'>{_e(value)}</dd>" for label, value in rows
    )
    return (
        f"<h1>{_e(REPORT_TITLE)}</h1>"
        "<p class='lede'>Deterministic assessment of collected technical evidence "
        "against an approved CRA control registry, with advisory remediation and "
        "the re-scan required to verify closure.</p>"
        f"<div class='disclaimer'><strong>Scope and status</strong>{_e(DISCLAIMER)}</div>"
        f"<div class='advisory'><strong>Remediation status</strong>{_e(ADVISORY_NOTICE)}</div>"
        f"<section class='panel'><dl class='meta'>{items}</dl></section>"
    )


def _action_summary(remediation: RemediationDocument) -> str:
    summary = remediation.summary
    tiles = [
        f"<li class='tile total'><div class='n'>{summary.items_total}</div>"
        f"<div class='k'>Remediation items</div></li>"
    ]
    for action in ActionType:
        tiles.append(
            f"<li class='tile {action.value.lower()}'>"
            f"<div class='n'>{summary.by_action_type.get(action.value, 0)}</div>"
            f"<div class='k'>{_e(ACTION_LABELS[action])}</div></li>"
        )
    for status in RemediationStatus:
        tiles.append(
            f"<li class='tile {status.value.lower()}'>"
            f"<div class='n'>{summary.by_status.get(status.value, 0)}</div>"
            f"<div class='k'>{_e(status.value.replace('_', ' '))}</div></li>"
        )
    tiles.append(
        f"<li class='tile'><div class='n'>{summary.controls_without_action}</div>"
        f"<div class='k'>No action required</div></li>"
    )
    return f"<h2>Remediation summary</h2><ul class='tiles'>{''.join(tiles)}</ul>"


def _findings_table(remediation: RemediationDocument) -> str:
    if not remediation.items:
        return (
            "<h2>Findings and remediation</h2>"
            "<section class='panel'><p>The assessment recorded no finding that "
            "requires an action.</p></section>"
        )
    rows = "".join(
        "<tr>"
        f"<td class='mono'>{_e(item.remediation_id)}</td>"
        f"<td class='mono'><a href='#{_e(item.remediation_id)}'>"
        f"{_e(item.finding_control_id)}</a></td>"
        f"<td>{_e(item.finding_title)}</td>"
        f"<td><span class='badge {_e(item.finding_verdict.value)}'>"
        f"{_e(item.finding_verdict.value)}</span></td>"
        f"<td><span class='badge {_e(item.action_type.value)}'>"
        f"{_e(ACTION_LABELS[item.action_type])}</span></td>"
        f"<td class='mono'>{_e(item.reason_code.value if item.reason_code else '')}</td>"
        f"<td><span class='badge {_e(item.status.value)}'>{_e(item.status.value)}</span></td>"
        "</tr>"
        for item in remediation.items
    )
    head = (
        "<tr><th>Remediation ID</th><th>Control</th><th>Title</th><th>Verdict</th>"
        "<th>Action</th><th>Reason code</th><th>Status</th></tr>"
    )
    return (
        "<h2>Findings and remediation</h2>"
        f"<table><thead>{head}</thead><tbody>{rows}</tbody></table>"
    )


def _verification_block(item: RemediationItem) -> str:
    requirement = item.verification
    if requirement is None:
        return ""
    rows = [
        ("Control", requirement.control_id),
        ("Registry version", requirement.registry_version),
        ("Registry hash", requirement.registry_hash),
        ("Evidence keys", ", ".join(requirement.evidence_keys) or "none"),
        ("MCP tools", ", ".join(requirement.mcp_tools) or "none"),
        ("Required verdict", requirement.required_post_verdict),
        ("Same target required", requirement.same_target_required),
    ]
    body = "".join(
        f"<dt>{_e(label)}</dt><dd class='mono'>{_e(value)}</dd>" for label, value in rows
    )
    return _field(
        "Verification requirement (re-scan through Flow 2 and Flow 3)",
        f"<dl class='meta'>{body}</dl>",
    )


def _item_detail(item: RemediationItem) -> str:
    parts = [
        f"<h3 id='{_e(item.remediation_id)}'>"
        f"<span class='mono'>{_e(item.finding_control_id)}</span> — {_e(item.finding_title)} "
        f"<span class='badge {_e(item.action_type.value)}'>"
        f"{_e(ACTION_LABELS[item.action_type])}</span></h3>"
    ]
    parts.append(
        _field(
            "Finding",
            f"<span class='badge {_e(item.finding_verdict.value)}'>"
            f"{_e(item.finding_verdict.value)}</span> "
            f"remediation <span class='mono'>{_e(item.remediation_id)}</span>, "
            f"status <span class='badge {_e(item.status.value)}'>{_e(item.status.value)}</span>",
        )
    )
    if item.recommendation:
        parts.append(_field("Approved recommendation", _e(item.recommendation)))
        parts.append(
            _field(
                "Recommendation source",
                f"<span class='mono'>{_e(item.recommendation_source)}</span>",
            )
        )
    parts.append(_field("Reason", _e(item.reason)))
    if item.reason_code:
        parts.append(_field("Reason code", f"<span class='mono'>{_e(item.reason_code.value)}</span>"))
    parts.append(_field("Observed state", _e(item.observed_state)))
    if item.failed_rule_refs:
        rules = "".join(
            f"<li><span class='mono'>{_e(ref)}</span></li>" for ref in item.failed_rule_refs
        )
        parts.append(_field("Approved rules that did not match", f"<ul class='plain'>{rules}</ul>"))
    if item.missing_evidence_keys:
        keys = "".join(
            f"<li><span class='mono'>{_e(key)}</span></li>" for key in item.missing_evidence_keys
        )
        parts.append(_field("Missing evidence", f"<ul class='plain'>{keys}</ul>"))
    parts.append(
        _field(
            "Evidence",
            f"<span class='mono'>{_e(', '.join(item.evidence_ids)) or 'none'}</span>",
        )
    )
    parts.append(
        _field(
            "Implementation",
            f"owner {_e(item.implementation_owner)}, automatic execution "
            f"{_e(item.automatic_execution)}",
        )
    )
    parts.append(_verification_block(item))
    return f"<section class='panel'>{''.join(p for p in parts if p)}</section>"


def _item_details(remediation: RemediationDocument) -> str:
    if not remediation.items:
        return ""
    body = "".join(_item_detail(item) for item in remediation.items)
    return f"<h2>Remediation detail and verification requirements</h2>{body}"


def _verdict_badge(verdict: Verdict | None) -> str:
    if verdict is None:
        return "not assessed"
    return f"<span class='badge {_e(verdict.value)}'>{_e(verdict.value)}</span>"


def _closure(verification: VerificationDocument | None) -> str:
    if verification is None:
        return ""
    meta = verification.metadata
    header = (
        f"<section class='panel'><dl class='meta'>"
        f"<dt>Previous run</dt><dd class='mono'>{_e(meta.previous_run_id)}</dd>"
        f"<dt>New run</dt><dd class='mono'>{_e(meta.new_run_id)}</dd>"
        f"<dt>Findings compared</dt><dd class='mono'>{verification.summary.findings_compared}</dd>"
        f"<dt>Verified closed</dt><dd class='mono'>{verification.summary.verified_closed}</dd>"
        f"<dt>Still open</dt><dd class='mono'>{verification.summary.still_open}</dd>"
        f"<dt>Blocked</dt><dd class='mono'>{verification.summary.blocked}</dd>"
        f"</dl></section>"
    )
    if not verification.baseline_comparable:
        code = verification.blocked_reason_code
        header += (
            "<div class='disclaimer'><strong>Verification blocked</strong>"
            f"{_e(code.value if code else '')} — the two assessments are not the "
            "same baseline, so no finding can be closed by this comparison.</div>"
        )
    rows = "".join(
        "<tr>"
        f"<td class='mono'>{_e(item.control_id)}</td>"
        f"<td>{_e(item.title)}</td>"
        f"<td><span class='badge {_e(item.previous_verdict.value)}'>"
        f"{_e(item.previous_verdict.value)}</span></td>"
        f"<td>{_verdict_badge(item.new_verdict)}</td>"
        f"<td><span class='badge {_e(item.outcome.value)}'>"
        f"{_e(OUTCOME_LABELS[item.outcome])}</span></td>"
        f"<td class='mono'>{_e(item.reason_code.value if item.reason_code else '')}</td>"
        f"<td>{_e(item.reason)}</td>"
        "</tr>"
        for item in verification.items
    )
    head = (
        "<tr><th>Control</th><th>Title</th><th>Previous verdict</th><th>New verdict</th>"
        "<th>Outcome</th><th>Reason code</th><th>Detail</th></tr>"
    )
    table = (
        f"<table><thead>{head}</thead><tbody>{rows}</tbody></table>"
        if verification.items
        else "<section class='panel'><p>The previous assessment recorded no finding "
        "to verify.</p></section>"
    )
    return f"<h2>Re-scan and closure status</h2>{header}{table}"


def render_final_html(
    assessment: Assessment,
    remediation: RemediationDocument,
    verification: VerificationDocument | None = None,
) -> str:
    """Render the final report as one self-contained HTML document."""
    body = "".join(
        [
            _mock_banner(assessment),
            _header(assessment, remediation),
            render_summary(assessment),
            _action_summary(remediation),
            _closure(verification),
            render_control_table(assessment),
            _findings_table(remediation),
            _item_details(remediation),
            render_human_review(assessment),
            render_limitations(assessment),
            render_details(assessment),
            f"<footer>{_e(REPORT_TITLE)} — run {_e(remediation.metadata.run_id)} — "
            f"generated {_e(remediation.metadata.generated_at)}. "
            "Verdicts come from the deterministic rule engine and recommendations "
            "from the approved control registry.</footer>",
        ]
    )
    title = f"{REPORT_TITLE} — {remediation.metadata.run_id}"
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_e(title)}</title>\n"
        f"<style>{STYLESHEET}{EXTRA_STYLESHEET}</style>\n</head>\n"
        f"<body>\n<main>{body}</main>\n</body>\n</html>\n"
    )
