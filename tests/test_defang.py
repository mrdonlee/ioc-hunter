"""Tests for defang/refang helpers."""

import pytest

from ioc_hunter.core.defang import defang, refang


@pytest.mark.parametrize(
    ("defanged", "expected"),
    [
        ("evil[.]com", "evil.com"),
        ("evil(.)com", "evil.com"),
        ("evil{.}com", "evil.com"),
        ("evil[dot]com", "evil.com"),
        ("hxxp://evil.com", "http://evil.com"),
        ("hxxps://evil[.]com/path", "https://evil.com/path"),
        ("hXXps://evil[.]com", "https://evil.com"),
        ("bad[at]evil[.]com", "bad@evil.com"),
        ("bad[@]evil[.]com", "bad@evil.com"),
        ("1[.]2[.]3[.]4", "1.2.3.4"),
        ("nothing to refang", "nothing to refang"),
    ],
)
def test_refang(defanged: str, expected: str) -> None:
    assert refang(defanged) == expected


@pytest.mark.parametrize(
    ("plain", "expected"),
    [
        ("evil.com", "evil[.]com"),
        ("https://evil.com/path", "hxxps://evil[.]com/path"),
        ("http://evil.com", "hxxp://evil[.]com"),
        ("bad@evil.com", "bad[@]evil[.]com"),
        ("1.2.3.4", "1[.]2[.]3[.]4"),
    ],
)
def test_defang(plain: str, expected: str) -> None:
    assert defang(plain) == expected


@pytest.mark.parametrize(
    "sample",
    [
        "https://evil.com/path",
        "bad@evil.com",
        "1.2.3.4",
        "ftp://files.evil.com",
    ],
)
def test_defang_refang_roundtrip(sample: str) -> None:
    assert refang(defang(sample)) == sample
