"""Tests for the report exporters."""

from __future__ import annotations

import json

import pytest

from ioc_hunter.core.types import IOC, IOCType
from ioc_hunter.exporters import to_json, to_markdown, to_misp, to_stix
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import SourceResult, Verdict


def _verdict(
    value: str,
    type_: IOCType,
    verdict: Verdict = Verdict.MALICIOUS,
    confidence: float = 0.85,
    tags: tuple[str, ...] = ("phishing",),
    references: tuple[str, ...] = ("https://urlhaus.abuse.ch/url/1/",),
) -> IOCVerdict:
    ioc = IOC(value=value, type=type_)
    return IOCVerdict(
        ioc=ioc,
        verdict=verdict,
        confidence=confidence,
        results=(
            SourceResult(
                source="vt",
                ioc_type=type_,
                ioc_value=value,
                verdict=verdict,
                score=0.9,
                tags=tags,
            ),
        ),
        tags=tags,
        references=references,
    )


@pytest.fixture
def sample_verdicts() -> list[IOCVerdict]:
    return [
        _verdict("1.2.3.4", IOCType.IPV4, Verdict.MALICIOUS, 0.95),
        _verdict("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS, 0.88),
        _verdict(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            IOCType.SHA256,
            Verdict.SUSPICIOUS,
            0.5,
        ),
        _verdict("8.8.8.8", IOCType.IPV4, Verdict.BENIGN, 0.7, tags=()),
    ]


# --- JSON --------------------------------------------------------------------


def test_json_is_valid_and_complete(sample_verdicts) -> None:
    blob = to_json(sample_verdicts)
    parsed = json.loads(blob)
    assert parsed["generator"] == "ioc-hunter"
    assert parsed["count"] == 4
    assert len(parsed["iocs"]) == 4
    first = parsed["iocs"][0]
    assert first["value"] == "1.2.3.4"
    assert first["type"] == "ipv4"
    assert first["verdict"] == "malicious"
    assert first["sources"][0]["source"] == "vt"


def test_json_compact_mode(sample_verdicts) -> None:
    blob = to_json(sample_verdicts, pretty=False)
    # Compact serialisation has no leading whitespace before keys.
    assert '\n  "' not in blob
    json.loads(blob)  # still valid JSON


# --- Markdown ----------------------------------------------------------------


def test_markdown_contains_summary_and_indicators(sample_verdicts) -> None:
    md = to_markdown(sample_verdicts)
    assert "# IOC Hunter Report" in md
    assert "## Summary" in md
    assert "MALICIOUS" in md
    # IOCs defanged for safe paste.
    assert "1[.]2[.]3[.]4" in md
    assert "evil[.]com" in md


def test_markdown_orders_by_confidence_desc(sample_verdicts) -> None:
    md = to_markdown(sample_verdicts)
    pos_high = md.index("1[.]2[.]3[.]4")
    pos_mid = md.index("evil[.]com")
    pos_low = md.index("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert pos_high < pos_mid < pos_low


# --- STIX --------------------------------------------------------------------


def test_stix_bundle_structure(sample_verdicts) -> None:
    bundle = json.loads(to_stix(sample_verdicts))
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert len(bundle["objects"]) == 4
    indicator = bundle["objects"][0]
    assert indicator["type"] == "indicator"
    assert indicator["spec_version"] == "2.1"
    assert indicator["pattern_type"] == "stix"


def test_stix_pattern_per_type(sample_verdicts) -> None:
    bundle = json.loads(to_stix(sample_verdicts))
    patterns = {obj["pattern"] for obj in bundle["objects"]}
    assert "[ipv4-addr:value = '1.2.3.4']" in patterns
    assert "[domain-name:value = 'evil.com']" in patterns
    assert any("file:hashes.'SHA-256'" in p for p in patterns)


def test_stix_confidence_integer(sample_verdicts) -> None:
    bundle = json.loads(to_stix(sample_verdicts))
    for obj in bundle["objects"]:
        assert isinstance(obj["confidence"], int)
        assert 0 <= obj["confidence"] <= 100


def test_stix_escapes_apostrophes() -> None:
    verdicts = [_verdict("evil's.com", IOCType.DOMAIN, Verdict.MALICIOUS)]
    bundle = json.loads(to_stix(verdicts))
    assert bundle["objects"][0]["pattern"] == r"[domain-name:value = 'evil\'s.com']"


def test_stix_skips_unsupported_types() -> None:
    verdicts = [_verdict("CVE-2024-1234", IOCType.CVE, Verdict.MALICIOUS)]
    bundle = json.loads(to_stix(verdicts))
    # CVE has no STIX pattern in our mapping — skipped, not crashed.
    assert bundle["objects"] == []


# --- MISP --------------------------------------------------------------------


def test_misp_event_structure(sample_verdicts) -> None:
    event = json.loads(to_misp(sample_verdicts))
    body = event["Event"]
    assert body["info"] == "IOC Hunter findings"
    assert body["analysis"] == "2"
    assert body["threat_level_id"] == "1"  # MALICIOUS present → High
    assert len(body["Attribute"]) == 4


def test_misp_attribute_types(sample_verdicts) -> None:
    event = json.loads(to_misp(sample_verdicts))
    types = {a["type"] for a in event["Event"]["Attribute"]}
    assert types == {"ip-dst", "domain", "sha256"}


def test_misp_to_ids_set_for_indicators(sample_verdicts) -> None:
    event = json.loads(to_misp(sample_verdicts))
    by_value = {a["value"]: a for a in event["Event"]["Attribute"]}
    assert by_value["1.2.3.4"]["to_ids"] is True
    assert by_value["8.8.8.8"]["to_ids"] is False  # benign


def test_misp_threat_level_for_no_malicious() -> None:
    verdicts = [_verdict("safe.com", IOCType.DOMAIN, Verdict.BENIGN, 0.9, tags=())]
    event = json.loads(to_misp(verdicts))
    assert event["Event"]["threat_level_id"] == "4"  # undefined


def test_misp_custom_event_info() -> None:
    verdicts = [_verdict("1.2.3.4", IOCType.IPV4, Verdict.MALICIOUS)]
    event = json.loads(to_misp(verdicts, event_info="Incident #4242"))
    assert event["Event"]["info"] == "Incident #4242"
