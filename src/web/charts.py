"""Charts rendered as SVG on the server.

There is no charting library and no client-side JavaScript. A segment is an
ordinary link, a tooltip is a native ``<title>``, and every chart is paired with
a text summary so the same information is available without seeing the picture.

These functions shape data that has already been computed. They never count
anything a service did not already count.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html import escape
from urllib.parse import quote

from src.assessment.models import Verdict
from src.evidence.models import CollectionStatus
from src.registry.models import ApplicabilityStatus

#: Status colours, matching the generated HTML reports so the two agree.
COLORS = {
    "pass": "#1a7f45",
    "fail": "#b3261e",
    "partial": "#8a6100",
    "insufficient": "#5b6572",
    "na": "#6b7280",
    "review": "#7a4fbf",
    "accent": "#1f4e79",
    "muted": "#98a2b3",
    "amber": "#c9971d",
}

VERDICT_COLORS = {
    Verdict.PASS: COLORS["pass"],
    Verdict.FAIL: COLORS["fail"],
    Verdict.PARTIAL: COLORS["partial"],
    Verdict.INSUFFICIENT_EVIDENCE: COLORS["insufficient"],
    Verdict.NOT_APPLICABLE: COLORS["na"],
    Verdict.HUMAN_REVIEW_REQUIRED: COLORS["review"],
}

#: Display order for verdicts wherever they are listed.
VERDICT_ORDER = [
    Verdict.PASS,
    Verdict.FAIL,
    Verdict.PARTIAL,
    Verdict.INSUFFICIENT_EVIDENCE,
    Verdict.NOT_APPLICABLE,
    Verdict.HUMAN_REVIEW_REQUIRED,
]

EVIDENCE_STATUS_COLORS = {
    CollectionStatus.COLLECTED: COLORS["pass"],
    CollectionStatus.TOOL_UNAVAILABLE: COLORS["amber"],
    CollectionStatus.TARGET_UNREACHABLE: COLORS["fail"],
    CollectionStatus.PERMISSION_DENIED: COLORS["fail"],
    CollectionStatus.PARSE_ERROR: COLORS["partial"],
    CollectionStatus.NOT_COLLECTED: COLORS["insufficient"],
}

APPLICABILITY_COLORS = {
    ApplicabilityStatus.APPLICABLE: COLORS["accent"],
    ApplicabilityStatus.CONDITIONAL: COLORS["partial"],
    ApplicabilityStatus.HUMAN_REVIEW_REQUIRED: COLORS["review"],
    ApplicabilityStatus.NOT_APPLICABLE: COLORS["na"],
}


@dataclass
class Segment:
    """One slice or bar: a label, a count, a colour and where clicking goes."""

    label: str
    value: int
    color: str
    href: str = ""
    note: str = ""

    @property
    def display(self) -> str:
        return self.label.replace("_", " ").title()


@dataclass
class Chart:
    """A rendered chart plus the data its text alternative is built from."""

    svg: str
    segments: list[Segment] = field(default_factory=list)
    total: int = 0
    empty: bool = True
    summary: str = ""


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _wrap(body: str, href: str, tooltip: str) -> str:
    """Attach a tooltip, and a link when the segment leads somewhere."""
    inner = f"<title>{_e(tooltip)}</title>{body}"
    if href:
        return f'<a href="{_e(href)}" class="seg">{inner}</a>'
    return f"<g>{inner}</g>"


def doughnut(segments: list[Segment], *, center_label: str = "", size: int = 190) -> Chart:
    """A doughnut where each slice is a link to the matching filtered view."""
    live = [s for s in segments if s.value > 0]
    total = sum(s.value for s in live)
    if total == 0:
        return Chart(
            svg="", segments=segments, total=0, empty=True, summary="No data yet."
        )

    radius = 60.0
    stroke = 26.0
    circumference = 2 * 3.141592653589793 * radius
    offset = 0.0
    parts: list[str] = []

    for segment in live:
        fraction = segment.value / total
        length = fraction * circumference
        percent = round(fraction * 100)
        circle = (
            f'<circle cx="80" cy="80" r="{radius}" fill="none" '
            f'stroke="{segment.color}" stroke-width="{stroke}" '
            f'stroke-dasharray="{length:.3f} {circumference - length:.3f}" '
            f'stroke-dashoffset="{-offset:.3f}" '
            f'transform="rotate(-90 80 80)" />'
        )
        tooltip = f"{segment.display}: {segment.value} of {total} ({percent}%)"
        if segment.note:
            tooltip = f"{tooltip} — {segment.note}"
        parts.append(_wrap(circle, segment.href, tooltip))
        offset += length

    center = (
        f'<text x="80" y="74" text-anchor="middle" class="dn-total">{total}</text>'
        f'<text x="80" y="92" text-anchor="middle" class="dn-label">{_e(center_label)}</text>'
    )
    svg = (
        f'<svg viewBox="0 0 160 160" width="{size}" height="{size}" class="chart doughnut" '
        f'role="img" aria-label="{_e(center_label)}: {total} total">'
        f"{''.join(parts)}{center}</svg>"
    )
    return Chart(
        svg=svg,
        segments=[s for s in segments],
        total=total,
        empty=False,
        summary=", ".join(f"{s.value} {s.display}" for s in live),
    )


def hbars(segments: list[Segment], *, width: int = 460, show_zero: bool = True) -> Chart:
    """Horizontal bars, one row per category, each row a link."""
    rows = segments if show_zero else [s for s in segments if s.value > 0]
    total = sum(s.value for s in segments)
    if not rows or total == 0:
        return Chart(
            svg="", segments=segments, total=0, empty=True, summary="No data yet."
        )

    peak = max(s.value for s in rows) or 1
    row_height = 30
    label_width = 200
    bar_area = width - label_width - 46
    height = row_height * len(rows) + 8
    parts: list[str] = []

    for index, segment in enumerate(rows):
        y = index * row_height + 4
        bar_width = (segment.value / peak) * bar_area if segment.value else 0
        body = (
            f'<rect x="0" y="{y}" width="{width}" height="{row_height}" '
            f'fill="transparent" class="row-hit" />'
            f'<text x="0" y="{y + 19}" class="bar-label">{_e(segment.display)}</text>'
            f'<rect x="{label_width}" y="{y + 6}" width="{max(bar_width, 2):.2f}" '
            f'height="15" rx="2" fill="{segment.color}" '
            f'{"opacity=\"0.25\"" if not segment.value else ""} />'
            f'<text x="{label_width + max(bar_width, 2) + 8:.2f}" y="{y + 19}" '
            f'class="bar-value">{segment.value}</text>'
        )
        tooltip = f"{segment.display}: {segment.value} of {total}"
        if segment.note:
            tooltip = f"{tooltip} — {segment.note}"
        parts.append(_wrap(body, segment.href if segment.value else "", tooltip))

    svg = (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'class="chart bars" role="img" aria-label="Distribution across {len(rows)} categories">'
        f"{''.join(parts)}</svg>"
    )
    return Chart(
        svg=svg,
        segments=rows,
        total=total,
        empty=False,
        summary=", ".join(f"{s.value} {s.display}" for s in rows if s.value),
    )


@dataclass
class TrendSeries:
    label: str
    color: str
    values: list[int]


def grouped_bars(
    run_labels: list[str], series: list[TrendSeries], *, width: int = 620
) -> Chart:
    """Counts across comparable runs, one group of bars per run."""
    if len(run_labels) < 2:
        return Chart(svg="", total=0, empty=True, summary="Needs two comparable runs.")

    height = 210
    pad_left = 34
    pad_bottom = 46
    plot_h = height - pad_bottom - 14
    peak = max((max(s.values) for s in series if s.values), default=0) or 1
    group_w = (width - pad_left - 12) / len(run_labels)
    bar_w = min(26.0, (group_w - 16) / max(len(series), 1))
    parts: list[str] = []

    for tick in range(0, 5):
        value = round(peak * tick / 4)
        y = 14 + plot_h - (value / peak) * plot_h
        parts.append(
            f'<line x1="{pad_left}" y1="{y:.1f}" x2="{width - 8}" y2="{y:.1f}" class="grid" />'
            f'<text x="{pad_left - 6}" y="{y + 4:.1f}" text-anchor="end" class="axis">{value}</text>'
        )

    for group, label in enumerate(run_labels):
        base_x = pad_left + group * group_w + 8
        for index, s in enumerate(series):
            value = s.values[group] if group < len(s.values) else 0
            bar_h = (value / peak) * plot_h
            x = base_x + index * (bar_w + 3)
            y = 14 + plot_h - bar_h
            body = (
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" '
                f'height="{max(bar_h, 1):.1f}" rx="2" fill="{s.color}" />'
            )
            parts.append(_wrap(body, "", f"{label} — {s.label}: {value}"))
        parts.append(
            f'<text x="{base_x + (group_w - 16) / 2:.1f}" y="{height - 26}" '
            f'text-anchor="middle" class="axis run">{_e(label)}</text>'
        )

    svg = (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'class="chart trend" role="img" aria-label="Verdict counts across '
        f'{len(run_labels)} comparable runs">{"".join(parts)}</svg>'
    )
    summary = "; ".join(
        f"{s.label}: " + " then ".join(str(v) for v in s.values) for s in series
    )
    return Chart(svg=svg, total=1, empty=False, summary=summary)


# --- data builders ----------------------------------------------------------


def verdict_segments(counts: dict[str, int], *, run_id: str = "") -> list[Segment]:
    """Chart A: verdict distribution, each slice filtering the Assessment page."""
    suffix = f"&run={quote(run_id)}" if run_id else ""
    return [
        Segment(
            label=verdict.value,
            value=counts.get(verdict.value, 0),
            color=VERDICT_COLORS[verdict],
            href=f"/assessment?verdict={verdict.value}{suffix}",
        )
        for verdict in VERDICT_ORDER
    ]


def evidence_segments(counts: dict[str, int], *, run_id: str = "") -> list[Segment]:
    """Chart B: collection health. This says nothing about compliance."""
    suffix = f"&run={quote(run_id)}" if run_id else ""
    return [
        Segment(
            label=status.value,
            value=counts.get(status.value, 0),
            color=EVIDENCE_STATUS_COLORS[status],
            href=f"/evidence?status={status.value}{suffix}",
        )
        for status in CollectionStatus
    ]


def applicability_segments(controls: list) -> list[Segment]:
    """Chart C: coverage, using the applicability the approved registry declares."""
    counts: dict[str, int] = {}
    for control in controls:
        counts[control.applicability.status.value] = (
            counts.get(control.applicability.status.value, 0) + 1
        )
    return [
        Segment(
            label=status.value,
            value=counts.get(status.value, 0),
            color=APPLICABILITY_COLORS[status],
            href=f"/registry?applicability={status.value}",
        )
        for status in ApplicabilityStatus
    ]
