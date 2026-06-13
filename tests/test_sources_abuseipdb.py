"""Tests for the AbuseIPDB source."""

from __future__ import annotations

import httpx
import pytest
import respx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.abuseipdb import AbuseIPDBSource
from ioc_hunter.sources.base import Verdict

_URL = "https://api.abuseipdb.com/api/v2/check"


def _payload(
    *,
    score: int = 0,
    whitelisted: bool = False,
    country: str | None = "RU",
    usage: str | None = "Data Center/Web Hosting/Transit",
    isp: str | None = "Bad ISP",
    last_reported: str | None = "2024-01-20T12:34:56+00:00",
) -> dict:
    return {
        "data": {
            "ipAddress": "1.2.3.4",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": whitelisted,
            "abuseConfidenceScore": score,
            "countryCode": country,
            "usageType": usage,
            "isp": isp,
            "totalReports": 543,
            "numDistinctUsers": 87,
            "lastReportedAt": last_reported,
        }
    }


@pytest.mark.asyncio
async def test_high_score_is_malicious(http_client: httpx.AsyncClient) -> None:
    src = AbuseIPDBSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(_URL).mock(return_value=httpx.Response(200, json=_payload(score=92)))
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.MALICIOUS
    assert result.score == pytest.approx(0.92)
    assert "country:RU" in result.tags
    assert any(t.startswith("isp:") for t in result.tags)


@pytest.mark.asyncio
async def test_mid_score_is_suspicious(http_client: httpx.AsyncClient) -> None:
    src = AbuseIPDBSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(_URL).mock(return_value=httpx.Response(200, json=_payload(score=40)))
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.score == pytest.approx(0.40)


@pytest.mark.asyncio
async def test_zero_score_is_unknown(http_client: httpx.AsyncClient) -> None:
    src = AbuseIPDBSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(_URL).mock(return_value=httpx.Response(200, json=_payload(score=0)))
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.UNKNOWN
    assert result.score == 0.0


@pytest.mark.asyncio
async def test_whitelisted_is_benign(http_client: httpx.AsyncClient) -> None:
    src = AbuseIPDBSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(_URL).mock(
            return_value=httpx.Response(200, json=_payload(score=100, whitelisted=True))
        )
        result = await src.lookup(IOCType.IPV4, "8.8.8.8")
    assert result.verdict is Verdict.BENIGN


@pytest.mark.asyncio
async def test_auth_header_sent(http_client: httpx.AsyncClient) -> None:
    src = AbuseIPDBSource(http_client, api_key="secret")
    with respx.mock() as router:
        route = router.get(_URL).mock(return_value=httpx.Response(200, json=_payload()))
        await src.lookup(IOCType.IPV4, "1.2.3.4")
    req = route.calls.last.request
    assert req.headers.get("Key") == "secret"
    assert req.headers.get("Accept") == "application/json"


@pytest.mark.asyncio
async def test_http_error_yields_error_result(
    http_client: httpx.AsyncClient,
) -> None:
    src = AbuseIPDBSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(_URL).mock(return_value=httpx.Response(429))
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is not None


@pytest.mark.asyncio
async def test_unsupported_type(http_client: httpx.AsyncClient) -> None:
    src = AbuseIPDBSource(http_client, api_key="K")
    result = await src.lookup(IOCType.DOMAIN, "evil.com")
    assert result.error is not None and "support" in result.error
