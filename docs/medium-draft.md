# Building a Multi-Source Threat Intelligence Correlation Engine in Python

> A SOC analyst's notes on going from "I want to learn async" to a working
> tool that other analysts can clone and use.

---

## TL;DR

I'm a SOC analyst learning Python and built **[IOC Hunter][repo]** —
an async tool that takes a chunk of text (phishing report, log dump,
Slack export), extracts every indicator inside, queries six threat-intel
sources in parallel, and produces a verdict you can drop into a ticket
or a SIEM.

This article is the *why* and the *how* — the architectural decisions
I had to think through, the things that bit me, and a small dose of
"what I learned about myself as an engineer."

[repo]: https://github.com/platinum2high/ioc-hunter

---

## The Problem

I sit in a SOC. The shape of my day is: alert fires → triage → mostly
boring → occasionally interesting → write a ticket.

The "occasionally interesting" part is where I noticed the same workflow
repeating. Someone forwards me a phishing email. The body has IPs,
URLs, hashes, an email address. Half of them are defanged
(`evil[.]com`, `hxxps://`, `bad[at]evil[.]com`). Some are
encoded — base64 in the headers, hex in the payload.

To triage, I do roughly this:

1. Refang each indicator by hand
2. Open VirusTotal, paste
3. Open AbuseIPDB, paste
4. Open URLhaus, paste
5. Mentally aggregate "VT says X, AbuseIPDB says Y, URLhaus has it as Z"
6. Decide
7. Write the ticket, paraphrasing the sources

This is a **30-minute manual process** for what should be **30 seconds**.
And most existing IOC checkers I found on GitHub were 1:1: one IOC in,
one source out. They didn't solve the workflow problem — they just
slightly automated step 2.

So I wrote one that solves the whole thing.

---

## What it actually does

```bash
$ ioc-hunter check "185[.]220[.]101[.]42"
```

Output (simplified):

```
╭─────── IOC Hunter ────────╮
│ 185[.]220[.]101[.]42      │
│ type: ipv4                │
│                           │
│ MALICIOUS  confidence 46% │
╰───────────────────────────╯

Source       Verdict      Score   Notes
─────────────────────────────────────────────
tor_exit     SUSPICIOUS    0.50   tor, anonymizer
abuseipdb    MALICIOUS     1.00   country:DE, isp:Tor-Exit traffic
otx          MALICIOUS     1.00   Bruteforce, SSH, Honeypot
virustotal   MALICIOUS     0.15   suspicious-udp, tor
urlhaus      UNKNOWN       0.00
threatfox    UNKNOWN       0.00
```

Six sources, queried in parallel, defanged on input *and* on output
(so you can paste the result into a chat without anyone clicking it),
weighted verdict with the **per-source contribution shown explicitly**
so you can defend the call in a ticket.

But the real feature is `scan-file` — drop in a 200-line incident
report, get back every indicator inside, each enriched, sorted by
confidence. And `correlate` finds the pivots: shared infrastructure,
shared malware tags, URL-to-host relationships across the batch.

---

## Architectural Decisions That Took Thought

### 1. The plugin pattern for sources

I want adding a new TI feed to be **one file, no other changes anywhere**.

```python
class Source(ABC):
    name: str
    weight: float
    supported_types: frozenset[IOCType]
    requires_key: bool = False

    @abstractmethod
    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        ...
```

Each source is a class with class-level metadata (`weight`,
`supported_types`, `requires_key`) and one method. The orchestrator
introspects the metadata to pick which sources to query for each IOC
and to skip ones whose key isn't configured.

This means I can drop in a Shodan source tomorrow and not touch the
engine, scorer, or CLI.

### 2. Graceful degradation > opinionated requirements

A naive design: "no API keys → tool doesn't work." A user-friendly
design: **every source short-circuits to UNKNOWN if its key is missing,
with an explanatory error message; the rest run normally**.

```python
@property
def is_configured(self) -> bool:
    return not self.requires_key or bool(self._api_key)
```

The orchestrator skips unconfigured sources before they ever fire a
request. So if you clone my repo and run it without registering for
anything, you still get a verdict — just from the one truly-keyless
source (Tor exit list). Five API keys unlock the rest.

This is the difference between "demo project" and "tool people actually
try." Anyone cloning it sees output in 30 seconds.

### 3. Transparent weighted scoring, not a black box

Every verdict comes with the per-source contribution. The scoring
formula is:

```python
weighted: dict[Verdict, float] = dict.fromkeys(Verdict, 0.0)
for r in valid_results:
    w = sources_by_name[r.source].weight
    if r.verdict in {MALICIOUS, SUSPICIOUS}:
        weighted[r.verdict] += w * max(r.score, MIN_PRESENCE_SCORE)
    elif r.verdict is BENIGN:
        weighted[r.verdict] += w
```

Then severity-prioritized thresholds (malicious share ≥ 25% wins, etc.).

The whole function is 30 lines. An analyst can read it and reproduce
the verdict on paper. That matters when defending a finding in an
incident review.

### 4. Async concurrency with a global cap

```python
class Engine:
    def __init__(self, sources, *, cache=None, max_concurrency=8):
        self._sem = asyncio.Semaphore(max_concurrency)

    async def _lookup_cached(self, ioc, source):
        if self._cache and (hit := self._cache.get(...)):
            return hit
        async with self._sem:
            return await source.lookup(...)
```

The semaphore is **shared across all sources and all IOCs**. So when
the analyst feeds in 100 IOCs, the engine doesn't slam every source
with 100 simultaneous requests — it pipelines them through the cap.

The free tiers of these APIs have rate limits (VirusTotal: 4
req/minute on free). Without the cap I'd hit 429s instantly.

---

## Things That Bit Me

### URLhaus and ThreatFox now require auth

Until mid-2024 they were truly keyless. The abuse.ch team added
`Auth-Key` requirement to fight scraper abuse. The key is free and
registration is instant, but my "everything-keyless" pitch had to
become "Tor-keyless, everything else free signup."

This is fine, but it taught me to **always link to the registration
URL from the error message** when a source short-circuits. Don't make
the user dig.

### VirusTotal URL IDs are not URLs

VT's v3 API expects URLs as `urlsafe-base64(url)` with padding
stripped. I lost an hour to this before reading their docs carefully:

```python
def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
```

### Rich's markup parser eats `[@]`

I render defanged values in the CLI: `bad@evil.com` →
`bad[@]evil[.]com`. Rich's table renderer interpreted `[@]` as a
(nonexistent) markup tag and silently stripped it. Output became
`badevil[.]com` — completely broken.

The fix is `rich.markup.escape()`:

```python
def _safe(value: str) -> str:
    return rich.markup.escape(defang(value))
```

I now wrap every IOC value in `_safe()` before passing to a Rich
component. Tests caught this only after I started writing the README —
the tests verified the verdict, not the rendered string.

### STIX 2.1 patterns need apostrophe-escaping

A domain IOC with an apostrophe (`it's.example.com` — weird but
possible) breaks the STIX pattern:

```
[domain-name:value = 'it's.example.com']  ← invalid
[domain-name:value = 'it\'s.example.com'] ← valid
```

Pattern values are single-quoted in STIX, so embedded apostrophes need
escaping. Took me a tracked-down-on-purpose test to catch it.

---

## The Boring Parts That Matter

If you read GitHub-shaped engineering posts, the "boring parts" — tests,
CI, lint, secret scanning, Docker hygiene — get one sentence at the
end. They probably deserve half the post.

**217 unit tests.** Every regex pattern, every source, every exporter,
every scorer threshold has a test. Network is mocked via `respx`. The
test suite runs in 0.7 seconds. I can refactor anything and know within
a second if I broke something.

**CI matrix.** Tests run on Python 3.11 and 3.12. Ruff lints and
format-checks. Docker image builds. Gitleaks scans the diff for
accidentally-committed secrets. Every PR has to pass all of this before
merging.

**Multi-stage Docker.** The runtime image is non-root, ~120 MB,
doesn't include test files or the wheel-builder layer. The cache
directory is a mounted volume so it survives container restarts.

None of this is impressive on its own. It's the table stakes that
separates "code I'd hire someone for" from "code I'd ask them to
explain in an interview."

---

## What I Learned About Myself

I started this thinking "I'll learn asyncio." I finished thinking
"asyncio was the easy part — the hard part was deciding what *not* to
build."

Half the work was saying no:

- No PyYAML for Sigma generation. Hand-write the YAML, save a
  dependency.
- No SQLAlchemy for the cache. Stdlib sqlite3 is enough.
- No "agent framework" for plugin sources. An ABC and a list is enough.
- No background daemon. A CLI is enough.
- No web UI. The Rich TUI is enough.

Every "is enough" is a thing I didn't have to test, document, maintain,
or explain to a hiring manager. The project is **6,000 lines of code
and 4 runtime dependencies** because of that discipline.

I think this is the real seniority signal. Anyone can add a dep. Not
everyone can leave one out.

---

## If You Want to Try It

```bash
git clone https://github.com/platinum2high/ioc-hunter
cd ioc-hunter
python -m venv .venv && source .venv/bin/activate
pip install -e .

ioc-hunter check "185[.]220[.]101[.]42"   # works keyless
ioc-hunter configure                        # walks through optional API keys
ioc-hunter scan-file examples/sample-incident.txt
```

Or with Docker:

```bash
cp .env.example .env
docker compose run --rm ioc-hunter check evil[.]com
```

The repo is MIT, the issue tracker is open, and I'd genuinely love
feedback from SOC analysts on the scoring model, defang patterns, and
sources I should add. (I'm thinking abuse.ch MalwareBazaar and GreyNoise
next.)

---

*Code: [github.com/platinum2high/ioc-hunter][repo]*

*Reach me on [LinkedIn](https://www.linkedin.com/) if you want to chat
about SOC tooling, threat intel, or detection engineering.*
