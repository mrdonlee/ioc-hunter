"""Tests for the abstract Source base class."""

from __future__ import annotations

import httpx
import pytest

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Source, SourceResult, Verdict


class _KeyedSource(Source):
    name = "keyed"
    weight = 1.0
    supported_types = frozenset({IOCType.IPV4})
    requires_key = True

    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        if not self.supports(ioc_type):
            return self._unsupported(ioc_type, ioc_value)
        if not self.is_configured:
            return self._missing_key(ioc_type, ioc_value)
        return SourceResult(
            source=self.name,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=Verdict.MALICIOUS,
            score=1.0,
        )


@pytest.mark.asyncio
async def test_supports_only_listed_types(http_client: httpx.AsyncClient) -> None:
    src = _KeyedSource(http_client, api_key="k")
    assert src.supports(IOCType.IPV4)
    assert not src.supports(IOCType.DOMAIN)


@pytest.mark.asyncio
async def test_unsupported_returns_error(http_client: httpx.AsyncClient) -> None:
    src = _KeyedSource(http_client, api_key="k")
    result = await src.lookup(IOCType.DOMAIN, "evil.com")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is not None and "support" in result.error


@pytest.mark.asyncio
async def test_missing_key_returns_error(http_client: httpx.AsyncClient) -> None:
    src = _KeyedSource(http_client, api_key=None)
    assert src.is_configured is False
    result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is not None and "API key" in result.error


@pytest.mark.asyncio
async def test_keyed_source_with_key_runs(http_client: httpx.AsyncClient) -> None:
    src = _KeyedSource(http_client, api_key="present")
    assert src.is_configured is True
    result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.MALICIOUS
    assert result.score == 1.0
    assert result.error is None
