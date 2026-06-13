"""Markdown report exporter — paste-into-ticket friendly."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from ioc_hunter.core.defang import defang
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import Verdict


def to_markdown(verdicts: list[IOCVerdict]) -> str:
    """Render a Markdown report. All IOC values are defanged for safe display."""
    now = datetime.now(UTC).isoformat(timespec="seconds")
    counts = Counter(v.verdict for v in verdicts)

    lines: list[str] = []
    lines.append("# IOC Hunter Report")
    lines.append("")
    lines.append(f"_Generated:_ `{now}`  |  _Indicators:_ **{len(verdicts)}**")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Verdict | Count |")
    lines.append("| ------- | ----- |")
    for verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.BENIGN, Verdict.UNKNOWN):
        lines.append(f"| {verdict.value.upper()} | {counts.get(verdict, 0)} |")
    lines.append("")
    lines.append("## Indicators")
    lines.append("")

    sorted_verdicts = sorted(verdicts, key=lambda v: (-v.confidence, v.ioc.value))
    for i, v in enumerate(sorted_verdicts, start=1):
        lines.append(
            f"### {i}. `{defang(v.ioc.value)}` — {v.ioc.type.value} — "
            f"**{v.verdict.value.upper()}** ({v.confidence:.0%})"
        )
        lines.append("")
        if v.tags:
            lines.append(f"**Tags:** {', '.join(v.tags[:25])}")
            lines.append("")
        lines.append("**Per-source results:**")
        lines.append("")
        lines.append("| Source | Verdict | Score | Notes |")
        lines.append("| ------ | ------- | ----- | ----- |")
        for r in v.results:
            notes = r.error or ", ".join(r.tags[:5])
            verdict_str = "error" if r.error else r.verdict.value
            lines.append(f"| {r.source} | {verdict_str} | {r.score:.2f} | {notes} |")
        lines.append("")
        if v.references:
            lines.append("**References:**")
            lines.append("")
            for ref in v.references[:10]:
                lines.append(f"- {ref}")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)
