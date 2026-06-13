"""Tests for the OTX source."""

from __future__ import annotations

import httpx
import pytest
import respx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Verdict
from ioc_hunter.sources.otx import OTXSource

_BASE = "https://otx.alienvault.com/api/v1/indicators"


def _payload(*, pulse_count: int, reputation: int = 0, tags: list[str] | None = None):
    return {
        "indicator": "1.2.3.4",
        "type": "IPv4",
        "reputation": reputation,
        "pulse_info": {
            "count": pulse_count,
            "pulses": [
                {"id": str(i), "name": f"pulse {i}", "tags": tags or []} for i in range(pulse_count)
            ],
        },
    }


@pytest.mark.asyncio
async def test_many_pulses_is_malicious(http_client: httpx.AsyncClient) -> None:
    src = OTXSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(f"{_BASE}/IPv4/1.2.3.4/general").mock(
            return_value=httpx.Response(200, json=_payload(pulse_count=8, tags=["apt", "c2"]))
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.MALICIOUS
    assert "apt" in result.tags
    assert "c2" in result.tags


@pytest.mark.asyncio
async def test_few_pulses_is_suspicious(http_client: httpx.AsyncClient) -> None:
    src = OTXSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(f"{_BASE}/IPv4/1.2.3.4/general").mock(
            return_value=httpx.Response(200, json=_payload(pulse_count=2))
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.SUSPICIOUS


@pytest.mark.asyncio
async def test_zero_pulses_is_unknown(http_client: httpx.AsyncClient) -> None:
    src = OTXSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(f"{_BASE}/IPv4/8.8.8.8/general").mock(
            return_value=httpx.Response(200, json=_payload(pulse_count=0))
        )
        result = await src.lookup(IOCType.IPV4, "8.8.8.8")
    assert result.verdict is Verdict.UNKNOWN


@pytest.mark.asyncio
async def test_negative_reputation_is_malicious(http_client: httpx.AsyncClient) -> None:
    src = OTXSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(f"{_BASE}/IPv4/1.2.3.4/general").mock(
            return_value=httpx.Response(200, json=_payload(pulse_count=1, reputation=-8))
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.MALICIOUS


@pytest.mark.asyncio
async def test_routes_by_ioc_type(http_client: httpx.AsyncClient) -> None:
    src = OTXSource(http_client, api_key="K")
    with respx.mock() as router:
        domain_route = router.get(f"{_BASE}/domain/evil.com/general").mock(
            return_value=httpx.Response(200, json=_payload(pulse_count=0))
        )
        file_route = router.get(f"{_BASE}/file/{'a' * 64}/general").mock(
            return_value=httpx.Response(200, json=_payload(pulse_count=0))
        )
        cve_route = router.get(f"{_BASE}/cve/CVE-2024-1234/general").mock(
            return_value=httpx.Response(200, json=_payload(pulse_count=0))
        )
        await src.lookup(IOCType.DOMAIN, "evil.com")
        await src.lookup(IOCType.SHA256, "a" * 64)
        await src.lookup(IOCType.CVE, "CVE-2024-1234")
    assert domain_route.called
    assert file_route.called
    assert cve_route.called


@pytest.mark.asyncio
async def test_auth_header_sent(http_client: httpx.AsyncClient) -> None:
    src = OTXSource(http_client, api_key="secret")
    with respx.mock() as router:
        route = router.get(f"{_BASE}/IPv4/1.2.3.4/general").mock(
            return_value=httpx.Response(200, json=_payload(pulse_count=0))
        )
        await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert route.calls.last.request.headers.get("X-OTX-API-KEY") == "secret"


@pytest.mark.asyncio
async def test_http_error_yields_error_result(
    http_client: httpx.AsyncClient,
) -> None:
    src = OTXSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(f"{_BASE}/IPv4/1.2.3.4/general").mock(return_value=httpx.Response(500))
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is not None
