# Промо-черновики

Это **не** часть кода — это шпаргалка с текстами для самостоятельной публикации
на Reddit / LinkedIn / Хабре / awesome-листах. Подгони под себя, не копируй
без правок (это палится).

---

## Reddit — r/blueteamsec

**Тон:** "feedback welcome", не "look at me". Сабреддиты любят технику и
не любят саморекламу. Постить с аккаунта где есть хоть какая-то история
комментов, иначе зафлажат как spam.

**Заголовок:**
```
[Tool] IOC Hunter — async multi-source TI correlation engine, feedback welcome
```

**Тело:**
```markdown
Hey blueteam, I'm a SOC analyst learning Python/async and built this as a
portfolio project. Posting for feedback before I claim it as "done" on my CV.

**What it does**
Paste in raw text (phishing email, report, log dump) — it extracts every
IOC, refangs them, queries 6 TI feeds in parallel, and gives you a
weighted verdict with per-source breakdown. Also exports STIX 2.1, MISP
events, and auto-generates Sigma + Suricata rules from confirmed hits.

**Differentiators vs the other 500 IOC checkers on GitHub**
- Works **keyless out of the box** — Tor exit source needs no signup
- Defang-aware on both input and output (analyst-friendly)
- Plugin pattern for sources — adding a new feed is one ~50-line file
- Correlation graph: finds shared /24, shared tags, URL→host pivots
  across a batch of IOCs
- CyberChef-style decoder with magic auto-detect (base64/hex/URL/JWT/gzip)
- 217 unit tests, CI matrix, gitleaks scan on every push

**Stack:** Python 3.11+, httpx (async), Rich (TUI), SQLite (TTL cache),
Docker.

Repo: https://github.com/platinum2high/ioc-hunter

Specifically looking for:
- Sanity check on the scoring model (is the weighted aggregation
  reasonable, or am I overthinking)
- Anything I missed in defang patterns
- Sources I should add (I'm thinking abuse.ch MalwareBazaar, GreyNoise)
- General "is this useful or did I reinvent another wheel"

Thanks for reading.
```

**Когда постить:** будний день, 14:00-17:00 по UTC (вторая половина рабочего
дня в США, утро в Европе).

---

## LinkedIn пост

**Тон:** профессиональный, но не сухой. Скрин SCREENSHOT/SVG из README
прикрепи как изображение (рекрутеры скроллят быстро).

```text
I just shipped IOC Hunter — an async threat-intelligence correlation
engine for SOC analysts. Built as part of my learning journey into the
deeper end of blue-team tooling.

Why I built it
Most IOC checkers are 1:1 lookups against a single source. When you're
triaging an incident you don't have one IOC — you have a report full of
them, half defanged, half encoded. So I built a tool that handles the
whole workflow:

→ Parses raw incident text into structured IOCs (auto-refangs evil[.]com,
  hxxp://, [at])
→ Queries VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, ThreatFox and
  the Tor exit list in parallel
→ Aggregates the results with a transparent weighted scoring model
→ Finds cross-IOC pivots (shared infrastructure, shared malware tags)
→ Exports STIX 2.1, MISP events, and auto-generates Sigma + Suricata
  detection rules

What I learned
- Async orchestration with httpx and asyncio.Semaphore
- Plugin-style architecture so adding a TI source is one file
- TTL-based SQLite caching that survives across runs
- CI/CD with GitHub Actions, gitleaks for secret scanning, Docker
  multi-stage builds for the runtime image
- The unglamorous but important parts: 217 unit tests, ruff lint/format,
  graceful degradation when API keys are missing

The code is open source (MIT). I'd love feedback from SOC and detection
engineering folks here.

🔗 https://github.com/platinum2high/ioc-hunter

#SOC #ThreatIntelligence #BlueTeam #Python #Cybersecurity #DetectionEngineering
```

---

## Awesome-list PR'ы

Эти ссылки — список где репу можно предложить. PR делаем коротким:

### 1. awesome-threat-intelligence
- https://github.com/hslatman/awesome-threat-intelligence
- Раздел: `## Tools` → подраздел `### IOC Management`
- Добавь строку:
  ```markdown
  - [IOC Hunter](https://github.com/platinum2high/ioc-hunter) — Async
    multi-source TI correlation engine with parsing, scoring, correlation,
    and STIX/MISP/Sigma/Suricata export. Python, MIT.
  ```

### 2. awesome-cybersecurity-blueteam
- https://github.com/fabacab/awesome-cybersecurity-blueteam
- Раздел: `### Incident Response tools`
- Та же строка.

### 3. awesome-incident-response
- https://github.com/meirwah/awesome-incident-response
- Раздел: `## IOC Tools`
- Та же строка.

**Как делать PR:**
1. Fork → правишь README → коммит → Pull Request
2. В описании PR: "Adding ioc-hunter — open-source TI correlation engine
   I built as a portfolio project. Hopefully a fit for this list."
3. PR'ы в awesome-листы обычно мёрджат за пару дней. Каждый смёрженный
   PR — постоянный трафик на твою репу.

---

## Хабр / Dev.to пост

**Идея:** "Как я писал IOC корреляционный движок — заметки SOC аналиста"
(подходит для Habr / Хабр). Полная статья на 10-15 минут чтения с
архитектурными решениями.

Структура:
1. Зачем (проблема: один источник недостаточно для триажа)
2. Что выбрал и почему (async, плагин-архитектура, transparent scoring)
3. Грабли (URLhaus в 2024 ввёл auth, VT URL ID — base64url, STIX 2.1
   pattern escaping)
4. Что получилось, что хочется улучшить
5. Ссылка на GitHub в самом конце (не вверху — иначе закроют)

**Когда:** через 1-2 недели после Reddit-поста. Дай репе обрасти первыми
звёздами от сабреддит-аудитории — будет легитимнее.

---

## Что НЕ делать

❌ Покупать звёзды/форки — палится, рекрутеры это видят и это убивает доверие
❌ Спам в Discord/Slack без contextс — забанят и репутация в минус
❌ Show HN сейчас — у тебя один шанс, лучше после полировки и нескольких
   итераций фидбека
❌ Постить во все сабреддиты сразу — таргетируй blueteamsec, AskNetsec,
   SecOps. Cybersecurity сабреддит слишком шумный, утонешь
