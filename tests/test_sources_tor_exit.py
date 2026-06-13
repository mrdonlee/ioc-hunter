"""Tests for the keyless Tor exit source."""

from __future__ import annotations

import httpx
import pytest
import respx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Verdict
from ioc_hunter.sources.tor_exit import TorExitSource

_LIST_URL = "https://check.torproject.org/torbulkexitlist"
_LIST_BODY = "1.2.3.4\n5.6.7.8\n# comment line\n9.9.9.9\n"


@pytest.mark.asyncio
async def test_hit_returns_suspicious(http_client: httpx.AsyncClient) -> None:
    src = TorExitSource(http_client)
    with respx.mock() as router:
        router.get(_LIST_URL).mock(return_value=httpx.Response(200, text=_LIST_BODY))
        result = await src.lookup(IOCType.IPV4, "5.6.7.8")
    assert result.verdict is Verdict.SUSPICIOUS
    assert "tor" in result.tags
    assert _LIST_URL in result.references


@pytest.mark.asyncio
async def test_miss_returns_unknown(http_client: httpx.AsyncClient) -> None:
    src = TorExitSource(http_client)
    with respx.mock() as router:
        router.get(_LIST_URL).mock(return_value=httpx.Response(200, text=_LIST_BODY))
        result = await src.lookup(IOCType.IPV4, "11.22.33.44")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is None


@pytest.mark.asyncio
async def test_comment_lines_skipped(http_client: httpx.AsyncClient) -> None:
    src = TorExitSource(http_client)
    with respx.mock() as router:
        router.get(_LIST_URL).mock(return_value=httpx.Response(200, text=_LIST_BODY))
        await src.lookup(IOCType.IPV4, "1.2.3.4")
    # The comment line should not be treated as an IP entry.
    assert "# comment line" not in src._exits  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_list_cached_across_calls(http_client: httpx.AsyncClient) -> None:
    src = TorExitSource(http_client)
    with respx.mock() as router:
        route = router.get(_LIST_URL).mock(return_value=httpx.Response(200, text=_LIST_BODY))
        await src.lookup(IOCType.IPV4, "1.2.3.4")
        await src.lookup(IOCType.IPV4, "9.9.9.9")
        await src.lookup(IOCType.IPV4, "11.22.33.44")
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_http_error_yields_error_result(http_client: httpx.AsyncClient) -> None:
    src = TorExitSource(http_client)
    with respx.mock() as router:
        router.get(_LIST_URL).mock(return_value=httpx.Response(503))
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is not None
    assert "fetch failed" in result.error


@pytest.mark.asyncio
async def test_unsupported_type(http_client: httpx.AsyncClient) -> None:
    src = TorExitSource(http_client)
    result = await src.lookup(IOCType.DOMAIN, "evil.com")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is not None and "support" in result.error
