"""Tests for the URLhaus source."""

from __future__ import annotations

import httpx
import pytest
import respx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Verdict
from ioc_hunter.sources.urlhaus import URLhausSource

_BASE = "https://urlhaus-api.abuse.ch/v1"


@pytest.mark.asyncio
async def test_malicious_online_url(http_client: httpx.AsyncClient) -> None:
    src = URLhausSource(http_client, api_key="K")
    with respx.mock() as router:
        router.post(f"{_BASE}/url/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "query_status": "ok",
                    "url_status": "online",
                    "threat": "malware_download",
                    "tags": ["redline", "botnet"],
                    "date_added": "2024-01-15 14:30:00 UTC",
                    "last_online": "2024-01-20 10:00:00 UTC",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
                },
            )
        )
        result = await src.lookup(IOCType.URL, "https://evil.com/x")
    assert result.verdict is Verdict.MALICIOUS
    assert result.score >= 0.9
    assert "redline" in result.tags
    assert result.first_seen == "2024-01-15 14:30:00 UTC"
    assert result.references == ("https://urlhaus.abuse.ch/url/123/",)


@pytest.mark.asyncio
async def test_offline_url_is_suspicious(http_client: httpx.AsyncClient) -> None:
    src = URLhausSource(http_client, api_key="K")
    with respx.mock() as router:
        router.post(f"{_BASE}/url/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "query_status": "ok",
                    "url_status": "offline",
                    "tags": [],
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/456/",
                },
            )
        )
        result = await src.lookup(IOCType.URL, "https://evil.com/x")
    assert result.verdict is Verdict.SUSPICIOUS
    assert 0.5 <= result.score < 0.9


@pytest.mark.asyncio
async def test_no_results_returns_unknown(http_client: httpx.AsyncClient) -> None:
    src = URLhausSource(http_client, api_key="K")
    with respx.mock() as router:
        router.post(f"{_BASE}/host/").mock(
            return_value=httpx.Response(200, json={"query_status": "no_results"})
        )
        result = await src.lookup(IOCType.DOMAIN, "evil.com")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is None


@pytest.mark.asyncio
async def test_host_endpoint_used_for_domain(
    http_client: httpx.AsyncClient,
) -> None:
    src = URLhausSource(http_client, api_key="K")
    with respx.mock() as router:
        host_route = router.post(f"{_BASE}/host/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "query_status": "ok",
                    "tags": ["c2"],
                    "firstseen": "2024-01-01 00:00:00 UTC",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/host/evil.com/",
                },
            )
        )
        result = await src.lookup(IOCType.DOMAIN, "evil.com")
    assert host_route.called
    assert result.verdict is Verdict.MALICIOUS
    assert "c2" in result.tags


@pytest.mark.asyncio
async def test_payload_endpoint_used_for_sha256(
    http_client: httpx.AsyncClient,
) -> None:
    src = URLhausSource(http_client, api_key="K")
    sample = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    with respx.mock() as router:
        route = router.post(f"{_BASE}/payload/").mock(
            return_value=httpx.Response(200, json={"query_status": "no_results"})
        )
        await src.lookup(IOCType.SHA256, sample)
    request = route.calls.last.request
    assert b"sha256_hash=" in request.content


@pytest.mark.asyncio
async def test_auth_header_sent(http_client: httpx.AsyncClient) -> None:
    src = URLhausSource(http_client, api_key="secret-key")
    with respx.mock() as router:
        route = router.post(f"{_BASE}/url/").mock(
            return_value=httpx.Response(200, json={"query_status": "no_results"})
        )
        await src.lookup(IOCType.URL, "https://evil.com/x")
    assert route.calls.last.request.headers.get("Auth-Key") == "secret-key"


@pytest.mark.asyncio
async def test_http_error_yields_error_result(
    http_client: httpx.AsyncClient,
) -> None:
    src = URLhausSource(http_client, api_key="K")
    with respx.mock() as router:
        router.post(f"{_BASE}/url/").mock(return_value=httpx.Response(500))
        result = await src.lookup(IOCType.URL, "https://evil.com/x")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is not None


@pytest.mark.asyncio
async def test_missing_key_short_circuits(http_client: httpx.AsyncClient) -> None:
    src = URLhausSource(http_client, api_key=None)
    # No routes registered — any HTTP call would raise.
    with respx.mock():
        result = await src.lookup(IOCType.URL, "https://evil.com/x")
    assert result.error is not None and "API key" in result.error


@pytest.mark.asyncio
async def test_unsupported_type(http_client: httpx.AsyncClient) -> None:
    src = URLhausSource(http_client, api_key="K")
    result = await src.lookup(IOCType.EMAIL, "bad@evil.com")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is not None and "support" in result.error
