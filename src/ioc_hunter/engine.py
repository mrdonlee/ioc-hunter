"""Async orchestrator that fans out IOCs across all configured TI sources.

For each IOC the engine:
1. Picks the subset of `active_sources` that supports the IOC's type.
2. For each (ioc, source) pair: cache lookup; on miss, call source under a
   semaphore that caps total in-flight HTTP requests.
3. Aggregates the per-source results via `scorer.score_results`.

The same shared semaphore is used across all IOCs and all sources so the
caller can run `lookup_many()` on hundreds of IOCs without melting the
remote APIs.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any

from ioc_hunter.cache import TICache
from ioc_hunter.core.types import IOC
from ioc_hunter.scorer import IOCVerdict, score_results
from ioc_hunter.sources.base import Source, SourceResult, Verdict


def _serialize(result: SourceResult) -> dict[str, Any]:
    """Pack a SourceResult into a JSON-friendly cache payload.

    `raw` is dropped — we don't need the full upstream blob to re-aggregate.
    """
    return {
        "verdict": str(result.verdict),
        "score": result.score,
        "tags": list(result.tags),
        "first_seen": result.first_seen,
        "last_seen": result.last_seen,
        "references": list(result.references),
    }


def _deserialize(source: str, ioc: IOC, data: dict[str, Any]) -> SourceResult:
    return SourceResult(
        source=source,
        ioc_type=ioc.type,
        ioc_value=ioc.value,
        verdict=Verdict(data["verdict"]),
        score=float(data.get("score") or 0.0),
        tags=tuple(data.get("tags") or ()),
        first_seen=data.get("first_seen"),
        last_seen=data.get("last_seen"),
        references=tuple(data.get("references") or ()),
    )


class Engine:
    """Async TI orchestrator with optional caching."""

    def __init__(
        self,
        sources: list[Source],
        *,
        cache: TICache | None = None,
        max_concurrency: int = 8,
    ) -> None:
        self._sources = sources
        self._sources_by_name = {s.name: s for s in sources}
        self._cache = cache
        self._sem = asyncio.Semaphore(max_concurrency)

    @property
    def active_sources(self) -> list[Source]:
        """Sources with required keys present."""
        return [s for s in self._sources if s.is_configured]

    async def lookup_one(self, ioc: IOC) -> IOCVerdict:
        applicable = [s for s in self.active_sources if s.supports(ioc.type)]
        if not applicable:
            return IOCVerdict(ioc, Verdict.UNKNOWN, 0.0, ())

        results = await asyncio.gather(*(self._lookup_cached(ioc, s) for s in applicable))
        return score_results(ioc, list(results), self._sources_by_name)

    async def lookup_many(self, iocs: Iterable[IOC]) -> list[IOCVerdict]:
        return await asyncio.gather(*(self.lookup_one(ioc) for ioc in iocs))

    async def _lookup_cached(self, ioc: IOC, source: Source) -> SourceResult:
        if self._cache is not None:
            cached = self._cache.get(source.name, ioc.type, ioc.value)
            if cached is not None:
                return _deserialize(source.name, ioc, cached.payload)

        async with self._sem:
            result = await source.lookup(ioc.type, ioc.value)

        if self._cache is not None and result.error is None:
            self._cache.set(source.name, ioc.type, ioc.value, _serialize(result))
        return result
