"""Tests for the weighted verdict scorer."""

from __future__ import annotations

from typing import Any

import httpx

from ioc_hunter.core.types import IOC, IOCType
from ioc_hunter.scorer import score_results
from ioc_hunter.sources.base import Source, SourceResult, Verdict


class _StubSource(Source):
    supported_types = frozenset({IOCType.IPV4, IOCType.DOMAIN, IOCType.SHA256})
    requires_key = False

    def __init__(self, name: str, weight: float) -> None:
        super().__init__(client=httpx.AsyncClient())
        self.name = name
        self.weight = weight

    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:  # pragma: no cover
        raise NotImplementedError


def _result(source: str, verdict: Verdict, score: float, **extra: Any) -> SourceResult:
    return SourceResult(
        source=source,
        ioc_type=IOCType.IPV4,
        ioc_value="1.2.3.4",
        verdict=verdict,
        score=score,
        **extra,
    )


_IOC = IOC(value="1.2.3.4", type=IOCType.IPV4)


def test_no_valid_results_is_unknown() -> None:
    sources = {"a": _StubSource("a", 1.0)}
    results = [_result("a", Verdict.UNKNOWN, 0.0, error="boom")]
    verdict = score_results(_IOC, results, sources)
    assert verdict.verdict is Verdict.UNKNOWN
    assert verdict.confidence == 0.0
    # All results (including errors) are preserved on the verdict.
    assert len(verdict.results) == 1


def test_strong_consensus_is_malicious() -> None:
    sources = {
        "vt": _StubSource("vt", 0.9),
        "abuse": _StubSource("abuse", 0.8),
        "otx": _StubSource("otx", 0.75),
    }
    results = [
        _result("vt", Verdict.MALICIOUS, 0.95),
        _result("abuse", Verdict.MALICIOUS, 0.90),
        _result("otx", Verdict.MALICIOUS, 0.80),
    ]
    verdict = score_results(_IOC, results, sources)
    assert verdict.verdict is Verdict.MALICIOUS
    assert verdict.confidence > 0.7


def test_single_malicious_among_unknowns_is_suspicious() -> None:
    sources = {
        "vt": _StubSource("vt", 0.9),
        "abuse": _StubSource("abuse", 0.8),
        "otx": _StubSource("otx", 0.75),
    }
    results = [
        _result("vt", Verdict.MALICIOUS, 0.95),
        _result("abuse", Verdict.UNKNOWN, 0.0),
        _result("otx", Verdict.UNKNOWN, 0.0),
    ]
    verdict = score_results(_IOC, results, sources)
    # One source out of three crossing weight threshold pushes to MALICIOUS;
    # otherwise SUSPICIOUS. With weight 0.9 / 2.45 = 36% share, hits
    # malicious threshold (0.25).
    assert verdict.verdict is Verdict.MALICIOUS


def test_single_suspicious_among_unknowns_is_suspicious() -> None:
    sources = {
        "vt": _StubSource("vt", 0.9),
        "abuse": _StubSource("abuse", 0.8),
    }
    results = [
        _result("vt", Verdict.SUSPICIOUS, 0.5),
        _result("abuse", Verdict.UNKNOWN, 0.0),
    ]
    verdict = score_results(_IOC, results, sources)
    assert verdict.verdict is Verdict.SUSPICIOUS


def test_all_benign_is_benign() -> None:
    sources = {
        "vt": _StubSource("vt", 0.9),
        "abuse": _StubSource("abuse", 0.8),
    }
    results = [
        _result("vt", Verdict.BENIGN, 0.0),
        _result("abuse", Verdict.BENIGN, 0.0),
    ]
    verdict = score_results(_IOC, results, sources)
    assert verdict.verdict is Verdict.BENIGN
    assert verdict.confidence > 0.5


def test_tags_and_refs_merged_and_deduped() -> None:
    sources = {
        "a": _StubSource("a", 0.5),
        "b": _StubSource("b", 0.5),
    }
    results = [
        _result(
            "a",
            Verdict.MALICIOUS,
            0.9,
            tags=("phishing", "malware"),
            references=("https://a.example/x",),
        ),
        _result(
            "b",
            Verdict.MALICIOUS,
            0.9,
            tags=("phishing", "c2"),
            references=("https://b.example/x",),
        ),
    ]
    verdict = score_results(_IOC, results, sources)
    assert set(verdict.tags) == {"phishing", "malware", "c2"}
    assert set(verdict.references) == {
        "https://a.example/x",
        "https://b.example/x",
    }


def test_errored_results_are_kept_but_not_scored() -> None:
    sources = {
        "vt": _StubSource("vt", 0.9),
        "abuse": _StubSource("abuse", 0.8),
    }
    results = [
        _result("vt", Verdict.MALICIOUS, 0.9),
        _result("abuse", Verdict.UNKNOWN, 0.0, error="ratelimited"),
    ]
    verdict = score_results(_IOC, results, sources)
    # Only the valid VT result counts; full weight is vt only.
    assert verdict.verdict is Verdict.MALICIOUS
    assert len(verdict.results) == 2  # both preserved
