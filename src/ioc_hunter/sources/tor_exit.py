"""Tor exit-relay reputation source — fully keyless.

Fetches the Tor Project's bulk exit list once per hour and answers IP lookups
from the in-memory set. A Tor exit is not inherently malicious, but it's a
strong contextual signal for incidents involving anonymous traffic.
"""

from __future__ import annotations

import time

import httpx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Source, SourceResult, Verdict

_TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
_REFRESH_SECONDS = 3_600


class TorExitSource(Source):
    name = "tor_exit"
    weight = 0.4
    supported_types = frozenset({IOCType.IPV4, IOCType.IPV6})
    requires_key = False

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        api_key: str | None = None,
    ) -> None:
        super().__init__(client, api_key=api_key)
        self._exits: frozenset[str] = frozenset()
        self._loaded_at: float = 0.0

    async def _ensure_list(self) -> None:
        if self._exits and time.time() - self._loaded_at < _REFRESH_SECONDS:
            return
        resp = await self._client.get(_TOR_LIST_URL, timeout=10)
        resp.raise_for_status()
        ips = {
            line.strip()
            for line in resp.text.splitlines()
            if line.strip() and not line.startswith("#")
        }
        self._exits = frozenset(ips)
        self._loaded_at = time.time()

    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        if not self.supports(ioc_type):
            return self._unsupported(ioc_type, ioc_value)
        try:
            await self._ensure_list()
        except httpx.HTTPError as exc:
            return self._error(ioc_type, ioc_value, f"fetch failed: {exc}")

        if ioc_value in self._exits:
            return SourceResult(
                source=self.name,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                verdict=Verdict.SUSPICIOUS,
                score=0.5,
                tags=("tor", "anonymizer"),
                references=(_TOR_LIST_URL,),
            )
        return SourceResult(
            source=self.name,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=Verdict.UNKNOWN,
        )
