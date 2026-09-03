"""Deterministic HTML renderer for the assessment.

The report is built from the assessment document by application templates. No
model generates markup. Output is a single self-contained file: inline styles,
no scripts and no external assets, so it can be archived or emailed as-is.

Raw evidence is referenced by evidence ID rather than copied in.
"""

from __future__ import annotations

from html import escape
from typing import Any

from src.assessment.models import (
    Assessment,
    ControlResult,
    SUMMARY_FIELD_BY_VERDICT,
    Verdict,
)
from src.display import application_label, scope_caption, target_env_label

REPORT_TITLE = "NetBoss-XT CRA Technical Readiness Assessment"

DISCLAIMER = (
    "This is an automated technical readiness assessment of observed host "
    "configuration. It is not a CRA certification, not a declaration of "
    "conformity, and not a statement of legal compliance. Verdicts describe "
    "only what the cited evidence shows at the time of collection."
)

#: Display order for the summary tiles and the verdict legend.
VERDICT_ORDER = [
    Verdict.PASS,
    Verdict.FAIL,
    Verdict.PARTIAL,
    Verdict.INSUFFICIENT_EVIDENCE,
    Verdict.NOT_APPLICABLE,
    Verdict.HUMAN_REVIEW_REQUIRED,
]

STYLESHEET = """
:root {
  --bg: #f6f7f9; --panel: #ffffff; --ink: #1c2128; --muted: #5b6572;
  --line: #d8dee6; --accent: #1f4e79;
  --pass: #1a7f45; --fail: #b3261e; --partial: #8a6100;
  --insufficient: #5b6572; --na: #6b7280; --review: #7a4fbf;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem 1.5rem; background: var(--bg); color: var(--ink);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
main { max-width: 1120px; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .35rem; color: var(--accent); }
h2 { font-size: 1.15rem; margin: 2rem 0 .75rem; padding-bottom: .35rem; border-bottom: 2px solid var(--line); }
h3 { font-size: 1rem; margin: 0 0 .5rem; }
section.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 1.1rem 1.25rem; margin-bottom: 1rem; }
p.lede { color: var(--muted); margin: 0 0 1.25rem; }
.disclaimer { background: #fff8e6; border: 1px solid #e3c766; border-left: 5px solid #c9971d; border-radius: 6px; padding: .9rem 1.1rem; margin: 1rem 0 1.5rem; }
.disclaimer strong { display: block; margin-bottom: .25rem; text-transform: uppercase; font-size: .78rem; letter-spacing: .06em; }
dl.meta { display: grid; grid-template-columns: max-content 1fr; gap: .35rem 1.25rem; margin: 0; }
dl.meta dt { color: var(--muted); font-size: .85rem; }
dl.meta dd { margin: 0; font-size: .85rem; }
.tiles { display: flex; flex-wrap: wrap; gap: .6rem; margin: 0; padding: 0; list-style: none; }
.tile { flex: 1 1 150px; background: var(--panel); border: 1px solid var(--line); border-top: 3px solid var(--line); border-radius: 6px; padding: .7rem .85rem; }
.tile .n { font-size: 1.5rem; font-weight: 600; }
.tile .k { font-size: .72rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
.tile.total { border-top-color: var(--accent); }
.tile.pass { border-top-color: var(--pass); } .tile.pass .n { color: var(--pass); }
.tile.fail { border-top-color: var(--fail); } .tile.fail .n { color: var(--fail); }
.tile.partial { border-top-color: var(--partial); } .tile.partial .n { color: var(--partial); }
.tile.insufficient_evidence { border-top-color: var(--insufficient); }
.tile.not_applicable { border-top-color: var(--na); }
.tile.human_review_required { border-top-color: var(--review); } .tile.human_review_required .n { color: var(--review); }
table { width: 100%; border-collapse: collapse; background: var(--panel); font-size: .86rem; }
th, td { text-align: left; padding: .55rem .7rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: #eef1f5; font-size: .74rem; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }
tbody tr:last-child td { border-bottom: none; }
.badge { display: inline-block; padding: .12rem .5rem; border-radius: 999px; font-size: .72rem; font-weight: 600; letter-spacing: .03em; color: #fff; white-space: nowrap; }
.badge.PASS { background: var(--pass); } .badge.FAIL { background: var(--fail); }
.badge.PARTIAL { background: var(--partial); } .badge.INSUFFICIENT_EVIDENCE { background: var(--insufficient); }
.badge.NOT_APPLICABLE { background: var(--na); } .badge.HUMAN_REVIEW_REQUIRED { background: var(--review); }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .82em; }
.field { margin: .6rem 0; }
.field .label { font-size: .72rem; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); margin-bottom: .15rem; }
.trace { width: 100%; font-size: .8rem; margin-top: .3rem; }
.trace td.ok { color: var(--pass); font-weight: 600; }
.trace td.no { color: var(--fail); font-weight: 600; }
.excerpt { color: var(--muted); font-style: italic; }
ul.plain { margin: .25rem 0 0; padding-left: 1.1rem; }
footer { color: var(--muted); font-size: .8rem; margin-top: 2rem; text-align: center; }
@media print { body { background: #fff; padding: 0; } section.panel, .tile { break-inside: avoid; } }
"""


def _e(value: Any) -> str:
    """Escape any value for HTML text content."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return escape(str(value), quote=True)


def _field(label: str, body: str) -> str:
    if not body:
        return ""
    return f'<div class="field"><div class="label">{_e(label)}</div><div>{body}</div></div>'


def _header(assessment: Assessment) -> str:
    meta = assessment.metadata
    rows = [
        ("Target Env", target_env_label(meta.target_id)),
        ("Application", application_label(meta.application_id) or "—"),
        ("Scan / run ID", meta.run_id),
        ("Assessment ID", meta.assessment_id),
        ("Registry version", meta.registry_version),
        ("Registry hash", meta.registry_hash),
        ("Evidence SHA-256", meta.evidence_sha256),
        ("Provider", meta.provider),
        ("LLM narration", meta.llm_narration),
        ("Report generated", meta.generated_at),
    ]
    items = "".join(
        f"<dt>{_e(label)}</dt><dd class='mono'>{_e(value)}</dd>" for label, value in rows
    )
    return (
        f"<h1>{_e(REPORT_TITLE)}</h1>"
        f"<p class='lede'>Deterministic assessment of collected technical evidence "
        f"against an approved CRA control registry.</p>"
        f"<div class='disclaimer'><strong>Scope and status</strong>{_e(DISCLAIMER)}</div>"
        f"<section class='panel'><dl class='meta'>{items}</dl></section>"
    )


def _summary(assessment: Assessment) -> str:
    summary = assessment.summary
    tiles = [f"<li class='tile total'><div class='n'>{summary.total}</div>"
             f"<div class='k'>Total controls</div></li>"]
    for verdict in VERDICT_ORDER:
        field = SUMMARY_FIELD_BY_VERDICT[verdict]
        tiles.append(
            f"<li class='tile {field}'><div class='n'>{getattr(summary, field)}</div>"
            f"<div class='k'>{_e(verdict.value.replace('_', ' '))}</div></li>"
        )
    return f"<h2>Summary</h2><ul class='tiles'>{''.join(tiles)}</ul>"


def _source_label(result: ControlResult) -> str:
    """A short citation of the binding source, for the overview table."""
    legal = result.source_traceability.get("legal_sources") or []
    if not legal:
        return ""
    first = legal[0]
    locator = first.get("source_locator") or {}
    parts = [str(first.get("document_id", ""))]
    if locator.get("annex"):
        parts.append(f"Annex {locator['annex']}")
    if locator.get("part"):
        parts.append(f"Part {locator['part']}")
    if locator.get("paragraph"):
        parts.append(f"({locator['paragraph']})")
    return " ".join(p for p in parts if p)


def _control_table(assessment: Assessment) -> str:
    rows = []
    for result in assessment.results:
        evidence = ", ".join(result.evidence_ids) or "none"
        rows.append(
            "<tr>"
            f"<td class='mono'><a href='#{_e(result.control_id)}'>{_e(result.control_id)}</a></td>"
            f"<td>{_e(result.title)}</td>"
            f"<td><span class='badge {_e(result.verdict.value)}'>"
            f"{_e(result.verdict.value)}</span></td>"
            f"<td class='mono'>{_e(evidence)}</td>"
            f"<td class='mono'>{_e(_source_label(result))}</td>"
            f"<td>{_e(result.reason)}</td>"
            f"<td>{'Yes' if result.remediation_required else 'No'}</td>"
            "</tr>"
        )
    head = (
        "<tr><th>Control ID</th><th>Title</th><th>Verdict</th><th>Evidence</th>"
        "<th>Source</th><th>Reason</th><th>Remediation required</th></tr>"
    )
    return (
        "<h2>Control results</h2>"
        f"<table><thead>{head}</thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _traceability(result: ControlResult) -> str:
    blocks = []
    labels = {
        "legal_sources": "Legal",
        "classification_sources": "Classification",
        "guidance_sources": "Guidance",
        "technical_reference_sources": "Technical reference",
    }
    for key, label in labels.items():
        for source in result.source_traceability.get(key) or []:
            locator = source.get("source_locator") or {}
            bits = [
                f"{name} {locator[name]}"
                for name in ("annex", "part", "section", "article", "paragraph", "clause")
                if locator.get(name)
            ]
            if locator.get("page"):
                bits.append(f"page {locator['page']}")
            excerpt = source.get("source_excerpt") or ""
            blocks.append(
                f"<li><strong>{_e(label)}</strong> — "
                f"<span class='mono'>{_e(source.get('document_id'))}</span> "
                f"{_e(', '.join(bits))} "
                f"[{_e(source.get('binding_status'))}]"
                f"<div class='excerpt'>{_e(excerpt)}</div></li>"
            )
    if not blocks:
        return ""
    return f"<ul class='plain'>{''.join(blocks)}</ul>"


def _trace_table(result: ControlResult) -> str:
    if not result.evaluator_trace:
        return ""
    rows = []
    for entry in result.evaluator_trace:
        rule = entry.rule
        expected = rule.get("value")
        expected_text = "" if rule.get("operator") in ("EXISTS", "NOT_EXISTS") else _e(expected)
        cls = "ok" if entry.matched else "no"
        rows.append(
            "<tr>"
            f"<td class='mono'>{_e(rule.get('path'))}</td>"
            f"<td class='mono'>{_e(rule.get('operator'))}</td>"
            f"<td class='mono'>{expected_text}</td>"
            f"<td class='mono'>{_e(entry.observed)}</td>"
            f"<td class='mono'>{_e(', '.join(entry.evidence_ids))}</td>"
            f"<td class='{cls}'>{'match' if entry.matched else 'no match'}</td>"
            "</tr>"
        )
    head = (
        "<tr><th>Path</th><th>Operator</th><th>Expected</th><th>Observed</th>"
        "<th>Evidence</th><th>Result</th></tr>"
    )
    return f"<table class='trace'><thead>{head}</thead><tbody>{''.join(rows)}</tbody></table>"


def _detail(result: ControlResult) -> str:
    parts = [
        f"<h3 id='{_e(result.control_id)}'>"
        f"<span class='mono'>{_e(result.control_id)}</span> — {_e(result.title)} "
        f"<span class='badge {_e(result.verdict.value)}'>{_e(result.verdict.value)}</span></h3>"
    ]
    parts.append(_field("Source traceability", _traceability(result)))
    parts.append(
        _field(
            "Legal requirement",
            f"<div class='excerpt'>{_e(result.legal_requirement.get('original_text'))}</div>",
        )
    )
    parts.append(_field("NMS interpretation", _e(result.nms_interpretation)))
    parts.append(_field("Technical control", _e(result.technical_control)))
    parts.append(_field("Expected state", _e(result.expected_state)))
    parts.append(_field("Observed state", _e(result.observed_state)))
    parts.append(
        _field("Evidence", f"<span class='mono'>{_e(', '.join(result.evidence_ids)) or 'none'}</span>")
    )

    if result.derived_paths:
        items = "".join(
            f"<li><span class='mono'>{_e(d.path)}</span> from "
            f"<span class='mono'>{_e(d.evidence_id)}</span> — {_e(d.basis)}</li>"
            for d in result.derived_paths
        )
        parts.append(_field("Derived observations", f"<ul class='plain'>{items}</ul>"))

    if result.evidence_gaps:
        items = "".join(
            f"<li><span class='mono'>{_e(g.evidence_key)}</span> — {_e(g.status)}"
            f"{f' / {_e(g.reason_code)}' if g.reason_code else ''}</li>"
            for g in result.evidence_gaps
        )
        parts.append(_field("Uncollected approved evidence", f"<ul class='plain'>{items}</ul>"))

    parts.append(_field("Evaluator trace", _trace_table(result)))
    if result.evaluator_error:
        parts.append(_field("Evaluator note", _e(result.evaluator_error)))
    parts.append(_field("Verdict", f"<span class='badge {_e(result.verdict.value)}'>"
                                   f"{_e(result.verdict.value)}</span> "
                                   f"severity {_e(result.severity)}"))
    parts.append(_field("Reason", _e(result.reason)))

    if result.remediation_required and result.remediation_seed:
        seed = result.remediation_seed.get("recommendation", "")
        parts.append(
            _field(
                "Remediation seed (context only, finalized in Flow 4)",
                _e(seed),
            )
        )

    return f"<section class='panel'>{''.join(p for p in parts if p)}</section>"


def _details(assessment: Assessment) -> str:
    body = "".join(_detail(result) for result in assessment.results)
    return f"<h2>Control detail</h2>{body}"


def _limitations(assessment: Assessment) -> str:
    if not assessment.limitations:
        return ""
    rows = "".join(
        "<tr>"
        f"<td class='mono'>{_e(limitation.code.value)}</td>"
        f"<td>{_e(limitation.detail)}</td>"
        f"<td class='mono'>{_e(', '.join(limitation.control_ids))}</td>"
        "</tr>"
        for limitation in assessment.limitations
    )
    head = "<tr><th>Code</th><th>Detail</th><th>Controls</th></tr>"
    return (
        "<h2>Limitations</h2>"
        f"<table><thead>{head}</thead><tbody>{rows}</tbody></table>"
    )


def _human_review(assessment: Assessment) -> str:
    if not assessment.human_review_items:
        return ""
    rows = "".join(
        "<tr>"
        f"<td class='mono'><a href='#{_e(item.control_id)}'>{_e(item.control_id)}</a></td>"
        f"<td>{_e(item.title)}</td>"
        f"<td><span class='badge {_e(item.verdict.value)}'>{_e(item.verdict.value)}</span></td>"
        f"<td>{_e(item.reason)}</td>"
        "</tr>"
        for item in assessment.human_review_items
    )
    head = "<tr><th>Control ID</th><th>Title</th><th>Verdict</th><th>Required decision</th></tr>"
    return (
        "<h2>Human review queue</h2>"
        f"<table><thead>{head}</thead><tbody>{rows}</tbody></table>"
    )


def render_html(assessment: Assessment, *, assessments_dir=None) -> str:
    """Render the assessment as one self-contained HTML document."""
    from pathlib import Path

    from src.compliance.mock_provider import MockComplianceProvider
    from src.compliance.report import concise_body
    from src.lifecycle.store import load_lifecycle
    from src.services import runs_service

    evidence = None
    try:
        evidence = runs_service.load_evidence(assessment.metadata.run_id)
    except Exception:
        evidence = None

    lifecycle = None
    try:
        if assessments_dir is not None:
            lifecycle = load_lifecycle(assessment.metadata.run_id, Path(assessments_dir))
        else:
            lifecycle = runs_service.load_lifecycle(assessment.metadata.run_id)
    except Exception:
        lifecycle = None

    remediation = None
    try:
        remediation = runs_service.load_remediation(assessment.metadata.run_id)
    except Exception:
        remediation = None

    view = MockComplianceProvider().from_artifacts(
        assessment=assessment,
        evidence=evidence,
        remediation=remediation,
        lifecycle=lifecycle,
    )
    mock = ""
    if assessment.metadata.provider == "mock":
        mock = (
            "<div class='disclaimer'><strong>SYNTHETIC / MOCK ASSESSMENT DATA</strong>"
            "Findings describe synthetic fixture data.</div>"
        )
    body = (
        f"<h1>{_e(REPORT_TITLE)}</h1>"
        f"<p class='lede'>{_e(scope_caption(assessment.metadata.target_id, assessment.metadata.application_id))}.</p>"
        f"<div class='disclaimer'><strong>Scope</strong>{_e(DISCLAIMER)}</div>"
        f"{mock}"
        f"{concise_body(view, include_remediation=False)}"
    )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_e(REPORT_TITLE)} — {_e(assessment.metadata.run_id)}</title>\n"
        f"<style>{STYLESHEET}</style>\n</head>\n<body>\n<main>{body}</main>\n</body>\n</html>\n"
    )


# Public aliases so the Flow 4 final report reuses this markup verbatim rather
# than growing a second, drifting copy of the assessment sections.
escape_value = _e
render_field = _field
render_summary = _summary
render_control_table = _control_table
render_human_review = _human_review
render_limitations = _limitations
render_details = _details
