"""Concise HTML fragments rendered from AssessmentView.

Used by Flow 3/4 downloadable reports and kept separate from the UI templates
so archived HTML stays self-contained (inline CSS, no JS).
"""

from __future__ import annotations

from html import escape
from typing import Any

from src.compliance.models import AssessmentView, FindingView, RemediationView


def _e(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return escape(str(value), quote=True)


def executive_summary(view: AssessmentView) -> str:
    s = view.summary
    bullets = "".join(f"<li>{_e(b)}</li>" for b in s.bullets)
    bullet_block = f"<ul>{bullets}</ul>" if bullets else ""
    tiles = (
        f"<ul class='tiles'>"
        f"<li class='tile total'><div class='n'>{s.assets_assessed}</div><div class='k'>Assets</div></li>"
        f"<li class='tile total'><div class='n'>{s.controls_assessed}</div><div class='k'>Controls</div></li>"
        f"<li class='tile pass'><div class='n'>{s.passed}</div><div class='k'>Passed</div></li>"
        f"<li class='tile fail'><div class='n'>{s.failed}</div><div class='k'>Failed</div></li>"
        f"<li class='tile human_review_required'><div class='n'>{s.review}</div><div class='k'>Human review</div></li>"
        f"<li class='tile partial'><div class='n'>{s.remediation_pending}</div><div class='k'>Remediation pending</div></li>"
        f"<li class='tile fail'><div class='n'>{s.critical_high_findings}</div><div class='k'>Critical / High</div></li>"
        f"</ul>"
    )
    return (
        "<h2>Executive summary</h2>"
        f"<section class='panel'>"
        f"<p><strong>Overall status:</strong> {_e(s.overall_status.value)}</p>"
        f"{tiles}{bullet_block}</section>"
    )


def outcomes_section(view: AssessmentView) -> str:
    """Concise lifecycle outcomes: initial vs remediated / reviewed passes."""
    s = view.summary
    after_rem = [
        c
        for c in view.controls
        if c.status.value == "PASS"
        and (c.initial_status and c.initial_status.value == "FAIL")
    ]
    after_review = [
        c
        for c in view.controls
        if c.status.value == "PASS"
        and (c.initial_status and c.initial_status.value == "REVIEW")
    ]
    remaining = [c for c in view.controls if c.status.value == "FAIL"]
    pending_review = [c for c in view.controls if c.status.value == "REVIEW"]

    parts = [
        "<h2>Outcomes</h2>",
        "<section class='panel'>",
        "<ul>",
        f"<li>Initially passed: {_e(s.initially_passed)}</li>",
        f"<li>Passed after remediation: {_e(s.passed_after_remediation)}</li>",
        f"<li>Passed after human review: {_e(s.passed_after_review)}</li>",
        f"<li>Remaining failed: {_e(s.remaining_failed)}</li>",
        f"<li>Pending human review: {_e(s.pending_human_review)}</li>",
        "</ul>",
        "</section>",
    ]

    def _detail(control) -> str:
        bits = [
            f"<p><strong>Control:</strong> {_e(control.control_id)} — {_e(control.title)}</p>",
            f"<p><strong>Initial status:</strong> "
            f"{_e(control.initial_status.value if control.initial_status else '—')}</p>",
        ]
        if control.finding:
            bits.append(f"<p><strong>Finding:</strong> {_e(control.finding)}</p>")
        if control.remediation:
            bits.append(f"<p><strong>Remediation:</strong> {_e(control.remediation)}</p>")
        if control.verification:
            bits.append(f"<p><strong>Verification:</strong> {_e(control.verification)}</p>")
        if control.analysis_reason:
            bits.append(f"<p><strong>Analysis:</strong> {_e(control.analysis_reason)}</p>")
        bits.append(f"<p><strong>Final status:</strong> {_e(control.status.value)}</p>")
        return "<section class='panel'>" + "".join(bits) + "</section>"

    for c in after_rem[:20]:
        parts.append(_detail(c))
    for c in after_review[:20]:
        parts.append(_detail(c))
    for c in remaining[:10]:
        parts.append(
            "<section class='panel'>"
            f"<p><strong>Control:</strong> {_e(c.control_id)} — remaining FAIL</p>"
            f"<p>{_e(c.finding or c.reason)}</p>"
            "</section>"
        )
    for c in pending_review[:10]:
        parts.append(
            "<section class='panel'>"
            f"<p><strong>Control:</strong> {_e(c.control_id)} — pending human review</p>"
            f"<p>{_e(c.reason or c.finding)}</p>"
            "</section>"
        )
    return "".join(parts)


def controls_table(view: AssessmentView) -> str:
    """Compact status list so every assessed control remains in the report."""
    if not view.controls:
        return ""
    rows = "".join(
        "<tr>"
        f"<td class='mono'>{_e(c.control_id)}</td>"
        f"<td>{_e(c.title)}</td>"
        f"<td><span class='badge {_e(c.status.value)}'>{_e(c.status.value)}</span></td>"
        f"<td>{_e(c.severity.value if c.severity.value != 'NONE' else '—')}</td>"
        "</tr>"
        for c in view.controls
    )
    head = "<tr><th>Control</th><th>Title</th><th>Status</th><th>Severity</th></tr>"
    return (
        "<h2>Controls</h2>"
        f"<table><thead>{head}</thead><tbody>{rows}</tbody></table>"
    )


def findings_table(findings: list[FindingView]) -> str:
    if not findings:
        return (
            "<h2>Findings</h2>"
            "<section class='panel'><p>No failed or review findings.</p></section>"
        )
    rows = "".join(
        "<tr>"
        f"<td class='mono'>{_e(f.control_id)}</td>"
        f"<td>{_e(f.asset_name)}</td>"
        f"<td><span class='badge {_e(f.status.value)}'>{_e(f.status.value)}</span></td>"
        f"<td>{_e(f.severity.value)}</td>"
        f"<td>{_e(f.finding)}</td>"
        f"<td class='mono'>{_e(', '.join(f.evidence_ids) or '—')}</td>"
        "</tr>"
        for f in findings
    )
    head = (
        "<tr><th>Control</th><th>Asset</th><th>Status</th>"
        "<th>Severity</th><th>Finding</th><th>Evidence</th></tr>"
    )
    return (
        "<h2>Findings</h2>"
        f"<table><thead>{head}</thead><tbody>{rows}</tbody></table>"
    )


def remediation_table(items: list[RemediationView]) -> str:
    if not items:
        return (
            "<h2>Remediation</h2>"
            "<section class='panel'><p>No remediation items.</p></section>"
        )
    rows = "".join(
        "<tr>"
        f"<td class='mono'>{_e(item.remediation_id)}</td>"
        f"<td>{_e(item.severity.value if item.severity.value != 'NONE' else '—')}</td>"
        f"<td class='mono'>{_e(item.control_id)}</td>"
        f"<td>{_e(item.asset_name)}</td>"
        f"<td>{_e(item.recommended_action)}</td>"
        f"<td>{_e(item.verification)}</td>"
        "</tr>"
        for item in items
    )
    head = (
        "<tr><th>ID</th><th>Priority</th><th>Control</th><th>Asset</th>"
        "<th>Recommended action</th><th>Verification</th></tr>"
    )
    return (
        "<h2>Remediation</h2>"
        f"<table><thead>{head}</thead><tbody>{rows}</tbody></table>"
    )


def audit_footer(view: AssessmentView) -> str:
    return (
        f"<footer>Run {_e(view.run_id)} · assessment {_e(view.assessment_id)} · "
        f"registry v{_e(view.registry_version)} {_e(view.registry_hash)} · "
        f"evidence {_e(view.evidence_sha256)} · generated {_e(view.generated_at)}. "
        "Verdicts are produced by the deterministic rule engine. "
        "This is not CRA certification.</footer>"
    )


def concise_body(view: AssessmentView, *, include_remediation: bool = True) -> str:
    parts = [
        executive_summary(view),
        outcomes_section(view),
        controls_table(view),
        findings_table(view.findings),
    ]
    if include_remediation:
        parts.append(remediation_table(view.remediations))
    parts.append(audit_footer(view))
    return "".join(parts)
