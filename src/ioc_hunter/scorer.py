"""Aggregate per-source SourceResults into a single weighted verdict.

The scoring model is intentionally simple and transparent — every result
contributes `source.weight * normalized_score` to a per-verdict bucket, and
the final verdict is chosen by share of total weight with severity
preference (MALICIOUS shadows SUSPICIOUS shadows BENIGN). This is the
"why was this flagged" answer a SOC analyst can reproduce on paper.
"""

from __future__ import annotations

from dataclasses import dataclass

from ioc_hunter.core.types import IOC
from ioc_hunter.sources.base import Source, SourceResult, Verdict

_MIN_PRESENCE_SCORE = 0.5
_MALICIOUS_THRESHOLD = 0.25
_SUSPICIOUS_THRESHOLD = 0.25
_BENIGN_THRESHOLD = 0.3


@dataclass(frozen=True, slots=True)
class IOCVerdict:
    """The aggregated final answer for one IOC."""

    ioc: IOC
    verdict: Verdict
    confidence: float
    results: tuple[SourceResult, ...]
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()


def score_results(
    ioc: IOC,
    results: list[SourceResult],
    sources_by_name: dict[str, Source],
) -> IOCVerdict:
    """Aggregate `results` into a single IOCVerdict."""
    valid = [r for r in results if r.error is None]
    if not valid:
        return IOCVerdict(ioc, Verdict.UNKNOWN, 0.0, tuple(results))

    total_weight = sum(sources_by_name[r.source].weight for r in valid) or 1.0

    weighted: dict[Verdict, float] = dict.fromkeys(Verdict, 0.0)
    for r in valid:
        w = sources_by_name[r.source].weight
        if r.verdict in {Verdict.MALICIOUS, Verdict.SUSPICIOUS}:
            # Presence in a feed is meaningful even with low per-source score.
            weighted[r.verdict] += w * max(r.score, _MIN_PRESENCE_SCORE)
        elif r.verdict is Verdict.BENIGN:
            weighted[r.verdict] += w

    malicious_share = weighted[Verdict.MALICIOUS] / total_weight
    sus_share = weighted[Verdict.SUSPICIOUS] / total_weight
    benign_share = weighted[Verdict.BENIGN] / total_weight

    if malicious_share >= _MALICIOUS_THRESHOLD:
        verdict = Verdict.MALICIOUS
        confidence = min(1.0, malicious_share + sus_share * 0.5)
    elif sus_share >= _SUSPICIOUS_THRESHOLD or weighted[Verdict.MALICIOUS] > 0:
        verdict = Verdict.SUSPICIOUS
        confidence = min(1.0, sus_share + malicious_share)
    elif benign_share >= _BENIGN_THRESHOLD:
        verdict = Verdict.BENIGN
        confidence = benign_share
    else:
        verdict = Verdict.UNKNOWN
        confidence = 0.0

    tags: list[str] = []
    seen_tags: set[str] = set()
    for r in valid:
        for t in r.tags:
            if t and t not in seen_tags:
                tags.append(t)
                seen_tags.add(t)

    refs: list[str] = []
    seen_refs: set[str] = set()
    for r in valid:
        for ref in r.references:
            if ref and ref not in seen_refs:
                refs.append(ref)
                seen_refs.add(ref)

    return IOCVerdict(
        ioc=ioc,
        verdict=verdict,
        confidence=confidence,
        results=tuple(results),
        tags=tuple(tags),
        references=tuple(refs),
    )
