"""Tests for the VirusTotal v3 source."""

from __future__ import annotations

import base64

import httpx
import pytest
import respx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Verdict
from ioc_hunter.sources.virustotal import VirusTotalSource, _vt_url_id

_BASE = "https://www.virustotal.com/api/v3"


def _stats(*, malicious: int, suspicious: int = 0, harmless: int = 70, undetected: int = 20):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "timeout": 0,
                },
                "tags": ["phishing"] if malicious else [],
                "first_submission_date": 1_700_000_000,
                "last_analysis_date": 1_710_000_000,
            }
        }
    }


@pytest.mark.asyncio
async def test_url_id_is_base64_url_no_padding() -> None:
    url = "https://evil.com/path?x=1"
    expected = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    assert _vt_url_id(url) == expected
    assert "=" not in _vt_url_id(url)


@pytest.mark.asyncio
async def test_many_malicious_is_malicious(http_client: httpx.AsyncClient) -> None:
    src = VirusTotalSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(f"{_BASE}/ip_addresses/1.2.3.4").mock(
            return_value=httpx.Response(200, json=_stats(malicious=12))
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.MALICIOUS
    assert "phishing" in result.tags


@pytest.mark.asyncio
async def test_one_malicious_is_suspicious(http_client: httpx.AsyncClient) -> None:
    src = VirusTotalSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(f"{_BASE}/domains/maybe.com").mock(
            return_value=httpx.Response(200, json=_stats(malicious=1))
        )
        result = await src.lookup(IOCType.DOMAIN, "maybe.com")
    assert result.verdict is Verdict.SUSPICIOUS


@pytest.mark.asyncio
async def test_only_harmless_is_benign(http_client: httpx.AsyncClient) -> None:
    src = VirusTotalSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(f"{_BASE}/ip_addresses/8.8.8.8").mock(
            return_value=httpx.Response(200, json=_stats(malicious=0))
        )
        result = await src.lookup(IOCType.IPV4, "8.8.8.8")
    assert result.verdict is Verdict.BENIGN


@pytest.mark.asyncio
async def test_404_is_unknown(http_client: httpx.AsyncClient) -> None:
    src = VirusTotalSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(f"{_BASE}/files/{'a' * 64}").mock(return_value=httpx.Response(404))
        result = await src.lookup(IOCType.SHA256, "a" * 64)
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is None


@pytest.mark.asyncio
async def test_url_lookup_uses_encoded_id(http_client: httpx.AsyncClient) -> None:
    src = VirusTotalSource(http_client, api_key="K")
    url = "https://evil.com/x"
    url_id = _vt_url_id(url)
    with respx.mock() as router:
        route = router.get(f"{_BASE}/urls/{url_id}").mock(
            return_value=httpx.Response(200, json=_stats(malicious=3))
        )
        await src.lookup(IOCType.URL, url)
    assert route.called


@pytest.mark.asyncio
async def test_auth_header_sent(http_client: httpx.AsyncClient) -> None:
    src = VirusTotalSource(http_client, api_key="secret")
    with respx.mock() as router:
        route = router.get(f"{_BASE}/ip_addresses/1.2.3.4").mock(
            return_value=httpx.Response(200, json=_stats(malicious=0))
        )
        await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert route.calls.last.request.headers.get("x-apikey") == "secret"


@pytest.mark.asyncio
async def test_http_error_yields_error_result(
    http_client: httpx.AsyncClient,
) -> None:
    src = VirusTotalSource(http_client, api_key="K")
    with respx.mock() as router:
        router.get(f"{_BASE}/ip_addresses/1.2.3.4").mock(return_value=httpx.Response(500))
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is not None


@pytest.mark.asyncio
async def test_unsupported_type(http_client: httpx.AsyncClient) -> None:
    src = VirusTotalSource(http_client, api_key="K")
    result = await src.lookup(IOCType.CVE, "CVE-2024-1234")
    assert result.error is not None and "support" in result.error


@pytest.mark.asyncio
async def test_missing_key_short_circuits(http_client: httpx.AsyncClient) -> None:
    src = VirusTotalSource(http_client, api_key=None)
    with respx.mock():
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.error is not None and "API key" in result.error
