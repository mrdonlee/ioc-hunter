"""Render SVG "screenshots" of every CLI surface for the README.

We reuse the real `cli.py` render helpers against handcrafted IOCVerdict
fixtures so the screenshots match the live tool exactly. Rich's
`Console(record=True).save_svg()` produces a vector image — committable
to the repo, readable on GitHub, no PIL / no GUI required.

Run with: `python examples/render_screenshots.py`
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.terminal_theme import MONOKAI

from ioc_hunter import cli
from ioc_hunter.core.types import IOC, IOCType
from ioc_hunter.correlator import Correlation
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import SourceResult, Verdict

OUTPUT_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _result(
    source: str,
    ioc_type: IOCType,
    ioc_value: str,
    verdict: Verdict,
    score: float = 0.0,
    tags: tuple[str, ...] = (),
    error: str | None = None,
) -> SourceResult:
    return SourceResult(
        source=source,
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        verdict=verdict,
        score=score,
        tags=tags,
        error=error,
    )


def _record(name: str, render_fn) -> None:
    console = Console(record=True, width=100, force_terminal=True)
    # Swap the cli module's console for the recording one during rendering.
    original = cli.console
    cli.console = console
    try:
        render_fn(console)
    finally:
        cli.console = original
    out = OUTPUT_DIR / f"{name}.svg"
    console.save_svg(str(out), title=f"ioc-hunter {name}", theme=MONOKAI)
    print(f"wrote {out.relative_to(OUTPUT_DIR.parent.parent)}")


def _verdict_tor() -> IOCVerdict:
    ioc = IOC(value="185.220.101.42", type=IOCType.IPV4)
    return IOCVerdict(
        ioc=ioc,
        verdict=Verdict.MALICIOUS,
        confidence=0.46,
        results=(
            _result("tor_exit", IOCType.IPV4, ioc.value, Verdict.SUSPICIOUS, 0.50, ("tor", "anonymizer")),
            _result("urlhaus", IOCType.IPV4, ioc.value, Verdict.UNKNOWN),
            _result("threatfox", IOCType.IPV4, ioc.value, Verdict.UNKNOWN),
            _result(
                "abuseipdb",
                IOCType.IPV4,
                ioc.value,
                Verdict.MALICIOUS,
                1.00,
                ("country:DE", "usage:Commercial", "isp:Tor-Exit traffic"),
            ),
            _result("otx", IOCType.IPV4, ioc.value, Verdict.MALICIOUS, 1.00, ("Bruteforce", "SSH", "Honeypot")),
            _result("virustotal", IOCType.IPV4, ioc.value, Verdict.MALICIOUS, 0.15, ("suspicious-udp", "tor")),
        ),
        tags=("tor", "anonymizer", "country:DE", "Bruteforce", "SSH", "Honeypot"),
        references=(
            "https://check.torproject.org/torbulkexitlist",
            "https://www.abuseipdb.com/check/185.220.101.42",
            "https://otx.alienvault.com/indicator/IPv4/185.220.101.42",
        ),
    )


def _verdicts_scan() -> list[IOCVerdict]:
    def vd(
        value: str,
        type_: IOCType,
        verdict: Verdict,
        confidence: float,
        hits: int,
        total: int,
        tags: tuple[str, ...] = (),
    ) -> IOCVerdict:
        results = tuple(
            _result(f"src{i}", type_, value, verdict if i < hits else Verdict.UNKNOWN)
            for i in range(total)
        )
        return IOCVerdict(
            ioc=IOC(value=value, type=type_),
            verdict=verdict,
            confidence=confidence,
            results=results,
            tags=tags,
        )

    return [
        vd("CVE-2024-21762", IOCType.CVE, Verdict.MALICIOUS, 1.00, 1, 1,
           ("actively_exploited_kev", "fortigate")),
        vd("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
           IOCType.SHA256, Verdict.MALICIOUS, 0.48, 4, 4, ("windows", "malware", "ioc")),
        vd("185.220.101.42", IOCType.IPV4, Verdict.MALICIOUS, 0.46, 6, 6,
           ("tor", "anonymizer", "Bruteforce")),
        vd("185.220.101.99", IOCType.IPV4, Verdict.MALICIOUS, 0.46, 6, 6,
           ("tor", "anonymizer", "Bruteforce")),
        vd("8.8.8.8", IOCType.IPV4, Verdict.BENIGN, 0.37, 6, 6,
           ("country:US", "isp:Google LLC")),
        vd("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS, 0.36, 4, 4,
           ("malware", "phishing")),
        vd("https://evil.com/login.php", IOCType.URL, Verdict.SUSPICIOUS, 0.13, 4, 4),
        vd("https://evil.com/install.exe", IOCType.URL, Verdict.UNKNOWN, 0.00, 4, 4),
        vd("bad@evil.com", IOCType.EMAIL, Verdict.UNKNOWN, 0.00, 1, 1),
    ]


def _correlations() -> list[Correlation]:
    url1 = IOC("https://evil.com/login.php", IOCType.URL)
    url2 = IOC("https://evil.com/install.exe", IOCType.URL)
    domain = IOC("evil.com", IOCType.DOMAIN)
    email = IOC("bad@evil.com", IOCType.EMAIL)
    ip1 = IOC("185.220.101.42", IOCType.IPV4)
    ip2 = IOC("185.220.101.99", IOCType.IPV4)
    return [
        Correlation(url1, domain, "url_to_host", "URL is hosted on evil.com"),
        Correlation(url2, domain, "url_to_host", "URL is hosted on evil.com"),
        Correlation(email, domain, "email_to_domain", "Email at evil.com"),
        Correlation(ip1, ip2, "shared_subnet", "both in 185.220.101.0/24"),
        Correlation(ip1, ip2, "shared_tag", "both tagged 'tor'"),
        Correlation(ip1, ip2, "shared_tag", "both tagged 'Bruteforce'"),
    ]


def render_check(console: Console) -> None:
    verdict = _verdict_tor()
    cli._render_verdict_panel(verdict)
    cli._render_per_source_table(verdict)
    cli._render_extras(verdict)


def render_scan(console: Console) -> None:
    verdicts = _verdicts_scan()
    console.print("Extracted [bold]10[/] IOC(s) from examples/sample-incident.txt")
    cli._render_batch_table(verdicts)


def render_correlate(console: Console) -> None:
    from rich.box import SIMPLE
    from rich.table import Table

    console.print("Extracted [bold]10[/] IOC(s)")
    edges = _correlations()
    table = Table(title=f"Correlations ({len(edges)})", box=SIMPLE)
    table.add_column("Kind", style="cyan")
    table.add_column("Source", overflow="fold")
    table.add_column("→", style="dim")
    table.add_column("Target", overflow="fold")
    table.add_column("Evidence", style="dim", overflow="fold")
    for e in edges:
        table.add_row(e.kind, cli._safe(e.source.value), "→", cli._safe(e.target.value), e.evidence)
    console.print(table)


def render_sources(console: Console) -> None:
    from rich.box import SIMPLE
    from rich.table import Table

    rows = [
        ("tor_exit", "active", 0.40, "ipv4, ipv6", "no"),
        ("urlhaus", "active", 0.85, "domain, ipv4, md5, sha256, url", "yes"),
        ("threatfox", "active", 0.85, "domain, email, ipv4, ipv6, md5, sha1, sha256, url", "yes"),
        ("abuseipdb", "active", 0.80, "ipv4, ipv6", "yes"),
        ("otx", "active", 0.75, "cve, domain, ipv4, ipv6, md5, sha1, sha256, url", "yes"),
        ("virustotal", "active", 0.90, "domain, ipv4, ipv6, md5, sha1, sha256, url", "yes"),
    ]
    table = Table(title="TI sources", box=SIMPLE)
    table.add_column("Source", style="cyan")
    table.add_column("Status")
    table.add_column("Weight", justify="right")
    table.add_column("Supports", style="dim", overflow="fold")
    table.add_column("Key required", style="dim")
    for name, status, weight, supports, req in rows:
        styled = f"[green]{status}[/]" if status == "active" else f"[yellow]{status}[/]"
        table.add_row(name, styled, f"{weight:.2f}", supports, req)
    console.print(table)


def render_decode(console: Console) -> None:
    from rich.box import SIMPLE
    from rich.table import Table

    table = Table(title="Magic decode — 2 candidate(s)", box=SIMPLE)
    table.add_column("Op", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("IOCs", justify="right")
    table.add_column("Decoded", overflow="fold")
    table.add_row("base64", "0.95", "2", "https://evil.com/login.php")
    table.add_row("rot13", "0.85", "0", "nUE0pUZ6Yl9yqzyfYzAioF9fo2qcov5jnUN=")
    console.print(table)


if __name__ == "__main__":
    _record("check", render_check)
    _record("scan-file", render_scan)
    _record("correlate", render_correlate)
    _record("sources", render_sources)
    _record("decode", render_decode)
    print(f"\nDone — {OUTPUT_DIR}")
