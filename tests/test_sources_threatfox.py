"""Tests for the ThreatFox source."""

from __future__ import annotations

import httpx
import pytest
import respx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Verdict
from ioc_hunter.sources.threatfox import ThreatFoxSource

_URL = "https://threatfox-api.abuse.ch/api/v1/"


def _hit(
    *,
    confidence: int = 80,
    malware: str = "RedLine Stealer",
    tags: list[str] | None = None,
    reference: str = "https://threatfox.abuse.ch/ioc/123/",
) -> dict:
    return {
        "id": "123",
        "ioc": "evil.com",
        "ioc_type": "domain",
        "threat_type": "payload_delivery",
        "malware": "win.redline_stealer",
        "malware_printable": malware,
        "confidence_level": confidence,
        "first_seen": "2024-01-15 14:30:00 UTC",
        "last_seen": "2024-01-20 10:00:00 UTC",
        "tags": tags if tags is not None else ["redline"],
        "reference": reference,
    }


@pytest.mark.asyncio
async def test_high_confidence_is_malicious(http_client: httpx.AsyncClient) -> None:
    src = ThreatFoxSource(http_client, api_key="K")
    with respx.mock() as router:
        router.post(_URL).mock(
            return_value=httpx.Response(
                200, json={"query_status": "ok", "data": [_hit(confidence=90)]}
            )
        )
        result = await src.lookup(IOCType.DOMAIN, "evil.com")
    assert result.verdict is Verdict.MALICIOUS
    assert result.score == 0.9
    assert "RedLine Stealer" in result.tags
    assert "redline" in result.tags
    assert result.references == ("https://threatfox.abuse.ch/ioc/123/",)


@pytest.mark.asyncio
async def test_low_confidence_is_suspicious(http_client: httpx.AsyncClient) -> None:
    src = ThreatFoxSource(http_client, api_key="K")
    with respx.mock() as router:
        router.post(_URL).mock(
            return_value=httpx.Response(
                200, json={"query_status": "ok", "data": [_hit(confidence=25)]}
            )
        )
        result = await src.lookup(IOCType.DOMAIN, "evil.com")
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.score == 0.25


@pytest.mark.asyncio
async def test_multiple_hits_aggregated(http_client: httpx.AsyncClient) -> None:
    src = ThreatFoxSource(http_client, api_key="K")
    hits = [
        _hit(
            confidence=40,
            malware="Emotet",
            tags=["emotet"],
            reference="https://threatfox.abuse.ch/ioc/1/",
        ),
        _hit(
            confidence=85,
            malware="RedLine",
            tags=["redline", "stealer"],
            reference="https://threatfox.abuse.ch/ioc/2/",
        ),
    ]
    with respx.mock() as router:
        router.post(_URL).mock(
            return_value=httpx.Response(200, json={"query_status": "ok", "data": hits})
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.score == 0.85
    assert result.verdict is Verdict.MALICIOUS
    assert set(result.references) == {
        "https://threatfox.abuse.ch/ioc/1/",
        "https://threatfox.abuse.ch/ioc/2/",
    }
    assert "Emotet" in result.tags
    assert "RedLine" in result.tags
    assert "redline" in result.tags
    assert "stealer" in result.tags


@pytest.mark.asyncio
async def test_no_result_returns_unknown(http_client: httpx.AsyncClient) -> None:
    src = ThreatFoxSource(http_client, api_key="K")
    with respx.mock() as router:
        router.post(_URL).mock(
            return_value=httpx.Response(200, json={"query_status": "no_result", "data": ""})
        )
        result = await src.lookup(IOCType.DOMAIN, "clean.com")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is None


@pytest.mark.asyncio
async def test_auth_header_sent(http_client: httpx.AsyncClient) -> None:
    src = ThreatFoxSource(http_client, api_key="secret")
    with respx.mock() as router:
        route = router.post(_URL).mock(
            return_value=httpx.Response(200, json={"query_status": "no_result"})
        )
        await src.lookup(IOCType.DOMAIN, "evil.com")
    assert route.calls.last.request.headers.get("Auth-Key") == "secret"


@pytest.mark.asyncio
async def test_search_term_in_request_body(http_client: httpx.AsyncClient) -> None:
    src = ThreatFoxSource(http_client, api_key="K")
    with respx.mock() as router:
        route = router.post(_URL).mock(
            return_value=httpx.Response(200, json={"query_status": "no_result"})
        )
        await src.lookup(IOCType.DOMAIN, "evil.com")
    body = route.calls.last.request.content
    assert b'"search_term":"evil.com"' in body or b'"search_term": "evil.com"' in body


@pytest.mark.asyncio
async def test_http_error_yields_error_result(
    http_client: httpx.AsyncClient,
) -> None:
    src = ThreatFoxSource(http_client, api_key="K")
    with respx.mock() as router:
        router.post(_URL).mock(return_value=httpx.Response(429))
        result = await src.lookup(IOCType.DOMAIN, "evil.com")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is not None


@pytest.mark.asyncio
async def test_missing_key_short_circuits(http_client: httpx.AsyncClient) -> None:
    src = ThreatFoxSource(http_client, api_key=None)
    with respx.mock():
        result = await src.lookup(IOCType.DOMAIN, "evil.com")
    assert result.error is not None and "API key" in result.error


@pytest.mark.asyncio
async def test_unsupported_type(http_client: httpx.AsyncClient) -> None:
    src = ThreatFoxSource(http_client, api_key="K")
    result = await src.lookup(IOCType.CVE, "CVE-2024-1234")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is not None and "support" in result.error
