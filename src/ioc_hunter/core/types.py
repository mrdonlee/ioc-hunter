"""IOC type enumeration and data model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class IOCType(StrEnum):
    """Supported indicator-of-compromise types."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"
    BTC_ADDRESS = "btc_address"


@dataclass(frozen=True, slots=True)
class IOC:
    """A normalized indicator of compromise.

    `value` is canonical (refanged, lowercase for domains/hashes/emails).
    `raw` preserves the original form when normalization changed it; it is
    excluded from equality and hashing so duplicates collapse cleanly.
    """

    value: str
    type: IOCType
    raw: str | None = field(default=None, compare=False, hash=False)
