"""Defang and refang IOC strings.

SOC analysts defang IOCs (`evil.com` → `evil[.]com`) so they cannot be
accidentally clicked in reports, tickets, and chats. We need both directions:

* `refang()` — normalize defanged input so downstream regexes match.
* `defang()` — make output safe to display.
"""

from __future__ import annotations

import re

# Order matters — longer markers first so shorter ones do not eat them.
_REFANG_PAIRS: tuple[tuple[str, str], ...] = (
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("fxps://", "ftps://"),
    ("fxp://", "ftp://"),
    ("[://]", "://"),
    ("[//]", "//"),
    ("[at]", "@"),
    ("(at)", "@"),
    ("[dot]", "."),
    ("(dot)", "."),
    ("{dot}", "."),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[:]", ":"),
    ("(:)", ":"),
    ("[@]", "@"),
)

_REFANG_COMPILED: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(re.escape(defanged), re.IGNORECASE), real) for defanged, real in _REFANG_PAIRS
)


def refang(text: str) -> str:
    """Convert defanged IOC markers back to their canonical form."""
    result = text
    for pattern, repl in _REFANG_COMPILED:
        result = pattern.sub(repl, result)
    return result


_SCHEME_DEFANG: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"https://", re.IGNORECASE), "hxxps://"),
    (re.compile(r"http://", re.IGNORECASE), "hxxp://"),
    (re.compile(r"ftps://", re.IGNORECASE), "fxps://"),
    (re.compile(r"ftp://", re.IGNORECASE), "fxp://"),
)


def defang(text: str) -> str:
    """Convert an IOC to a non-clickable form for safe display.

    `https://evil.com/path` → `hxxps://evil[.]com/path`
    `bad@evil.com`          → `bad[@]evil[.]com`
    `1.2.3.4`               → `1[.]2[.]3[.]4`
    """
    result = text
    for pattern, repl in _SCHEME_DEFANG:
        result = pattern.sub(repl, result)
    result = result.replace(".", "[.]")
    result = result.replace("@", "[@]")
    return result
