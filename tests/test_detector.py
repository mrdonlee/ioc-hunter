"""Tests for single-string IOC type detection."""

import pytest

from ioc_hunter.core.detector import detect_type
from ioc_hunter.core.types import IOCType


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.8", IOCType.IPV4),
        ("192.168.1.1", IOCType.IPV4),
        ("255.255.255.255", IOCType.IPV4),
        ("2001:db8::1", IOCType.IPV6),
        ("::1", IOCType.IPV6),
        ("evil.com", IOCType.DOMAIN),
        ("sub.evil.co.uk", IOCType.DOMAIN),
        ("https://evil.com/login", IOCType.URL),
        ("http://1.2.3.4", IOCType.URL),
        ("ftp://files.example.com", IOCType.URL),
        ("bad@evil.com", IOCType.EMAIL),
        ("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IOCType.SHA1),
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            IOCType.SHA256,
        ),
        ("CVE-2021-44228", IOCType.CVE),
        ("cve-2024-1234", IOCType.CVE),
        ("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", IOCType.BTC_ADDRESS),
        (
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
            IOCType.BTC_ADDRESS,
        ),
    ],
)
def test_detect_positive(value: str, expected: IOCType) -> None:
    assert detect_type(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "not an ioc",
        "256.256.256.256",  # invalid octet
        "1.2.3",  # incomplete IP
        "abc",  # bare word, no TLD
        "evil.x",  # 1-char TLD
        "1234567890abcdef",  # 16 hex — not a hash
        "CVE-99-1",  # malformed CVE year
    ],
)
def test_detect_negative(value: str) -> None:
    assert detect_type(value) is None
