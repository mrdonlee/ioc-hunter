# IOC Hunter

> Async threat intelligence correlation engine for SOC analysts.
> Parses raw text into IOCs, queries multiple TI sources in parallel, scores
> them with a transparent weighted model, exports to STIX/MISP, and generates
> Sigma/Suricata detection rules.

![CI](https://img.shields.io/badge/CI-pending-lightgrey)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-WIP-orange)

---

## Why another IOC checker?

Most IOC tools do flat 1:1 lookups against a single source. **IOC Hunter** is
built to match how an analyst actually triages an incident:

- **Drag in raw text** — paste an email body, a report, a Slack export. IOC
  Hunter extracts every IP, domain, URL, hash, email, CVE, and crypto address.
- **Defang-aware** — understands `evil[.]com`, `hxxps://`, `1.2.3[.]4` and
  refangs them transparently. No analyst should have to clean strings by hand.
- **Multi-source async** — queries AbuseIPDB, AlienVault OTX, VirusTotal,
  URLhaus, ThreatFox in parallel. Slow source doesn't block the rest.
- **Transparent confidence** — not "bad/good." Every verdict shows the
  contribution from each source, with reliability weights you can tune.
- **Correlation** — feed it 50 IOCs from an incident, get back a graph of
  shared infrastructure pivots.
- **Built-in decoder** — base64, hex, URL, JWT, ROT, gzip, and 50+ more
  operations via [`chepy`](https://github.com/securisec/chepy). Auto-decode
  mode unwraps obfuscated payloads before extracting IOCs.
- **Exporters that fit a real workflow** — JSON, Markdown, STIX 2.1,
  MISP event, and auto-generated Sigma / Suricata rules.
- **Plugin sources** — add a new TI feed by dropping one file into
  `sources/`.

## Quickstart

```bash
# Install from source
git clone https://github.com/platinum2high/ioc-hunter && cd ioc-hunter
pip install -e .

# Interactive setup — collects API keys, writes .env
ioc-hunter configure

# Check a single IOC
ioc-hunter check 185.220.101.42

# Extract & enrich every IOC from a file
ioc-hunter scan-file incident.eml --auto-decode --report report.md

# Export STIX 2.1 bundle
ioc-hunter report --in iocs.txt --format stix --out bundle.json
```

### Run with Docker

```bash
cp .env.example .env  # fill in your keys
docker compose run --rm ioc-hunter check evil[.]com
```

## Architecture

```
                   ┌───────────────┐
   raw text ─────▶│  parser/defang │
                   └──────┬────────┘
                          ▼
                   ┌───────────────┐    cache hit ──▶ result
                   │  SQLite cache │───┐
                   └──────┬────────┘   │ miss
                          ▼            ▼
            ┌──────────────────────────────────────┐
            │   async orchestrator (httpx)         │
            │   ┌────────┬────────┬────────┐       │
            │   │URLhaus │ OTX    │ VT     │  ...  │
            │   └────────┴────────┴────────┘       │
            └──────────────────┬───────────────────┘
                               ▼
                       ┌────────────────┐
                       │ weighted scorer│
                       └──────┬─────────┘
                              ▼
                       ┌────────────────┐
                       │  correlator    │
                       └──────┬─────────┘
                              ▼
              ┌────────────────────────────────┐
              │ exporters: JSON/MD/STIX/MISP   │
              │ rule gen: Sigma/Suricata       │
              │ TUI dashboard                  │
              └────────────────────────────────┘
```

## Status

WIP — building in public, phase-by-phase. See the
[issue tracker](https://github.com/platinum2high/ioc-hunter/issues) for the roadmap.

| Phase | Status |
| ----- | ------ |
| 0  Project skeleton                | done |
| 1  IOC parser + defang             | todo |
| 2  SQLite cache                    | todo |
| 3  Keyless sources (URLhaus, ThreatFox) | todo |
| 4  Keyed sources (AbuseIPDB, OTX, VT)   | todo |
| 5  Async engine + weighted scorer   | todo |
| 6  CLI + Rich TUI                   | todo |
| 7  Exporters (JSON/MD/STIX/MISP)   | todo |
| 8  Correlation graph                | todo |
| 9  Sigma/Suricata rule generator    | todo |
| 10 Chepy-based decoder              | todo |
| 11 Docker, CI, README polish        | todo |

## Security

If you find a vulnerability, please open a private security advisory on
GitHub rather than a public issue.

API keys live in `.env` (gitignored). The repo is scanned by `gitleaks` on
every push.

## License

MIT — see [LICENSE](LICENSE).
