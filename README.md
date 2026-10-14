# Web Investigator

The optional **Dark-web references** workspace collects exact-domain mentions from
supplied onion URLs using free Tor access. It includes queued runs, source coverage,
and JSON evidence exports in both React and Streamlit. See
[setup and collection limits](docs/darkweb_collection.md). Automatic dark-web
discovery is not enabled in this pilot.

Web Investigator combines public web scraping and OSINT evidence collection with VirusTotal intelligence and external-job processing.

## React interface

The React interface runs beside the existing Streamlit application during migration. Docker builds the TypeScript source, so Node.js does not need to be installed on the host.

```bash
docker compose up -d --build web
```

Open `http://localhost:3000`. Streamlit remains available at `http://localhost:8501`, and FastAPI remains available at `http://localhost:8000`.

## OSINT foundation

The OSINT workspace currently provides:

- URL, domain, partial-name, and brand/application input classification
- Search-backed candidate-domain resolution with confidence and reasons
- Candidate selection or multi-domain analysis
- YAML-driven evidence query generation from `config/search_queries.yaml`
- 50 categorized evidence queries with IDs and priorities
- Public discovery queries for X, Reddit, Telegram, Facebook, Instagram, LinkedIn, YouTube, TikTok, Discord and GitHub
- Passive DNS and RDAP collection
- Public homepage, robots.txt and sitemap discovery
- Social-profile, document, JavaScript and APK/IPA link extraction
- Aggregated keyless search through Bing RSS, DuckDuckGo, and self-hosted SearXNG, with optional Brave Search API support
- Search-result URL normalization and deduplication
- Source classification and query-to-source traceability
- Bounded public-result collection with manual-required logging for protected pages
- Query-derived, case-insensitive evidence matching on public SERP result pages
- DOM-safe keyword highlighting and bounded Playwright viewport screenshots
- Screenshot SHA-256 provenance, surrounding text, source rank, and query linkage
- Evidence gallery and self-contained evidence screenshots in HTML reports
- Structured PostgreSQL persistence with evidence hashes (SQLite remains available for isolated tests)
- Explainable risk scoring and collector status reporting
- Downloadable, source-traceable HTML report
- Safe HTTPS/HTTP domain availability checks for resolved and related domains, with redirect validation
- Optional Similarweb estimated monthly/yearly visits in Streamlit, HTML, JSON, CSV, and DOCX exports

The module does not bypass authentication or scrape private platform data. Keyless web search is available without an API key. Brave can optionally be enabled:

```bash
export BRAVE_SEARCH_API_KEY="your-api-key"
```

Optional collection controls:

```bash
export OSINT_QUERY_BUDGET=12
export OSINT_RESULTS_PER_QUERY=10
export OSINT_REQUEST_TIMEOUT=10
export OSINT_SEARCH_REQUEST_DELAY=0.25
export OSINT_SEARCH_CACHE_TTL=86400
export OSINT_SOURCE_CRAWL_BUDGET=8
export OSINT_SOURCE_REQUEST_DELAY=0.5
export OSINT_MAX_ARTIFACT_BYTES=5000000
export OSINT_EVIDENCE_SOURCE_BUDGET=8
export MAX_SCREENSHOTS_PER_SOURCE=5
export PAGE_WORKERS=3
export OSINT_PAGE_TIMEOUT_MS=30000
export OSINT_EVIDENCE_HEADLESS=true
export OSINT_SEARCH_LANGUAGE=en
# Used automatically by Docker Compose; set it when running the app outside Docker:
export SEARXNG_URL=http://localhost:8080
export OSINT_DISABLE_SEARXNG=false
# Set true only when you want to disable keyless search:
export OSINT_DISABLE_KEYLESS_SEARCH=false
```

## Domain status and traffic estimates

Every resolved or related domain is checked with HTTPS first and HTTP fallback. The checker validates DNS and every redirect destination, blocks private/loopback/reserved addresses, uses bounded non-rendering requests, and treats access restrictions (403, CAPTCHA/WAF, 429) as proof that a domain is active. A single failed check does not stop the scan.

Traffic cannot be inferred from search results or page visits. The optional Similarweb integration returns **estimated visits**, not exact analytics. It requires a Similarweb API key (and is therefore optional; no traffic values are invented when it is absent). Copy `.env.example` to `.env`, export its values in your shell, then configure:

```bash
export TRAFFIC_PROVIDER=similarweb
export SIMILARWEB_API_KEY="your_similarweb_api_key"
```

Without these credentials, reports show `Unavailable` with a `not_configured` status and the missing-key reason. Set the key in the existing `.env` (do not overwrite that file), then recreate the app/workers to load it. Traffic is retrieved independently of target website access, including when a target blocks the browser or no longer resolves.

The API request asks for worldwide visits over the last 12 completed months. Monthly visits use the latest dated result. Yearly visits sum 12 consecutive months when present; otherwise the latest month × 12 is explicitly labelled `Projected`. Both are provider estimates, never exact analytics. Values are sorted by month and missing values are not converted to zero.

Successful estimates are cached for seven days; empty or failed lookups are retried. If a refresh fails, a previous estimate is retained as `stale` with its original date. In the Resolution tab, **Refresh traffic only** updates traffic without rerunning website checks. The table and exports show the data month, yearly basis, traffic status and failure reason. Similarweb API access and subscription coverage remain required; blocked public endpoints are not used as a fallback.

Brand and partial-name resolution uses the keyless provider when Brave is not configured. Complete URLs and domains resolve locally without any search request.

Run the application:

```bash
.venv/bin/streamlit run app.py
```

## Run the complete framework with Docker

Docker Compose runs Streamlit, FastAPI, workers, PostgreSQL 16, Redis, and a private SearXNG service. SearXNG is part of the same Compose project but runs in its own isolated container; it is reachable by the application and workers without being exposed to the host network. The stack does not read or modify the SQLite database in the original `Web-Investigator` repository.

The `schema_migrations` table tracks OSINT storage schema versions.

```bash
cp .env.example .env
# Change POSTGRES_PASSWORD in .env, then start everything:
docker compose up --build -d
```

Open <http://localhost:8501>. Check status and logs with:

```bash
docker compose ps
docker compose logs -f app
docker compose logs -f searxng
```

### VirusTotal intelligence workspace

The separate **VirusTotal intelligence** workspace retrieves existing VirusTotal v3 reports for domains, URLs, IP addresses, and file hashes. It stores the complete response in PostgreSQL and provides normalized dashboard results, a DOCX report, and the original JSON response.

Add the API key only to the untracked `.env` file:

```bash
VIRUSTOTAL_API_KEY=your_private_api_key
docker compose up -d --build app
```

Never add the real key to `.env.example`, source code, screenshots, reports, or Git. The first implementation is read-only and does not submit targets for rescanning.

SearXNG uses its JSON API and participates as the third keyless provider. Results from all available providers are normalized and deduplicated. A SearXNG or upstream-engine failure is recorded for audit purposes and does not prevent Bing RSS or DuckDuckGo results from completing the query. Set `OSINT_DISABLE_SEARXNG=true` in `.env` to disable only this provider.

The first FastAPI service boundary runs independently at <http://localhost:8000>. Interactive OpenAPI documentation is available at <http://localhost:8000/docs>.

```bash
curl http://localhost:8000/health/ready
curl http://localhost:8000/api/v1/investigations
curl "http://localhost:8000/api/v1/investigations?component=osint"
```

Long-running web-scraping and OSINT investigations can be submitted to FastAPI and executed by the separate worker through Redis. PostgreSQL keeps durable job status while Redis transports queued job IDs.

```bash
curl -X POST http://localhost:8000/api/v1/jobs/osint \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com","collectors":["DNS","RDAP","Public website"],"brand":"Example","authorized":true}'

curl http://localhost:8000/api/v1/jobs/JOB_ID_FROM_RESPONSE
```

The Streamlit UI submits OSINT jobs through these FastAPI endpoints and provides a dedicated external-job monitor. It polls job status in lightweight Streamlit fragments and links completed external jobs to their generated reports.

Stop the containers without deleting PostgreSQL data:

```bash
docker compose down
```

The named `postgres_data` and `redis_data` volumes persist database records and queued work. Do not run `docker compose down -v` unless you intentionally want to delete that fresh data.

Run the OSINT and evidence-capture tests:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Example inputs:

```text
Parimatch
parimatch123
parimatchs123.com
https://parimatchs123.com
```

## Collection reliability and interpreting results

A finished worker job means processing ended. The investigation is `PARTIAL` if any
collector or capture was unavailable; a successful DNS lookup does not override
failed evidence collection. The dashboard, HTML, DOCX, and investigation-detail API
include collection coverage. Historical records retain their original stored status,
but their reports calculate coverage from saved collector and page outcomes.

Risk scores describe collected indicators only. A zero score is **not a safety finding**.
`Not assessed` means no scored indicators were available. Even completed collection
covers only selected collectors, query depth, and source budgets, not the entire web.

The target homepage is prioritized for browser capture. Static assets such as CSS,
JavaScript, images, and fonts remain discovery leads but do not consume page-capture
slots. PDF/DOCX collection retains its separate budget (100 downloads by default).

Transient HTTP connection failures and browser navigation resets/timeouts receive
one retry. TLS validation, public-address checks, redirect checks, access restrictions,
and CAPTCHA handling remain enforced. Each browser source gets 90 seconds after a
page-worker slot becomes available; queue waiting does not consume that deadline.
Repeated search-provider failures trigger a 30-second batch-local cooldown. SearXNG
upstream failures and unrecognized/challenge search pages are reported explicitly;
empty keyless responses are not cached for a day.

Compose passes the collection and provider settings in `.env.example` to both the
app and workers. Set actual credentials only in `.env`. After changing settings or
source code, rebuild/recreate the services (`docker compose up -d --build app api worker`)
once active investigations have finished. No configured API key can guarantee access
to every target. Inspect collector errors and page capture diagnostics for restrictions
or connection failures that require operator follow-up.

## Advisory AI relevance review

New Docker investigations enable LM Studio review via `OSINT_LLM_REVIEW_ENABLED=true`.
The configured LAN endpoint is `http://10.244.1.54:1234`, model `google/gemma-4-e4b`.
The versioned instructions live in `config/relevance_review.txt`.

New investigations record worker-side website, saved-session and model readiness checks.
Saved browser state means configured, not proven logged in; social collectors check live
pages and distinguish explicit empty searches from login, challenge and selector failures.
A limited HTTP probe does not suppress browser capture. A failed model probe is checked
again when review starts. Readiness details and source-backed target identity are available
in the dashboard and report exports.

The supplied URL's path, query, subdomain and HTTP(S) scheme are preserved for the primary
job. Static resources and media references are excluded before page and text-review budgets;
response content types provide a second check. These references remain stored as diagnostics.
Target profiles contain names/languages explicitly declared by the website and observed
outbound social links, with source provenance. These associations do not establish ownership.

Social collectors attempt up to `SOCIAL_POST_CAPTURE_LIMIT=8` individual posts per platform,
within `SOCIAL_POST_CAPTURE_STAGE_SECONDS=60` and `SOCIAL_POST_CAPTURE_TIMEOUT_SECONDS=12`
per post. Search-discovered social and review links that were not captured by an authenticated
collector receive a separate public browser budget controlled by `OSINT_PUBLIC_SOCIAL_CAPTURE_BUDGET=8`.
per visit. Original snippets remain when detail capture fails or reaches a budget. Captures
record text scope, author/time when available, truncation and separate screenshot provenance.
YouTube captures descriptions, not video contents. Platform layout changes can still require
collector updates; an unsupported layout is reported rather than treated as zero results.

Two bounded stages run: discovery snippets before capture, then collected page excerpts,
social/review text, and extracted document excerpts. Social platforms and content kinds
are interleaved within the content-review budget. Supported relevant discovery leads are
promoted within the capture queue, after the input target. Other leads are retained;
existing capture budgets still limit how many pages are opened. Existing deterministic
collector/relevance filters still apply before this advisory review; this does not recover
content already rejected or inaccessible to those collectors.

AI output is not verified evidence and never adds risk points or removes stored evidence.
It appears in a separate dashboard expander, HTML/DOCX sections, and JSON export. The
provenance download includes exact supplied passages, cited passage IDs, model identifier,
prompt version/hash, successful input hash, raw answer, stage, source URL and timestamp.
Long inputs use bounded passages selected around target references throughout the supplied
text, with exact offsets and a hash of that supplied text. This does not imply the collector
retrieved the entire remote document. Negative decisions may cite the passages explaining
why the source does not match.
Model-proposed links must already occur in the supplied link list; the reviewer does not
invent or automatically follow additional URLs. Current link candidates are source URLs.

This is text-only: social captions/post text and extracted document text are reviewed.
The integration does not inspect video frames, perform OCR, or transcribe audio. Those
require separate collection adapters before they can become review inputs.

Defaults: 12 unique items per stage, a 15-second request timeout, and a 60-second stage
budget. Two request/validation failures stop that stage early. A timeout or invalid JSON
is recorded as an unavailable, uncertain review; unreviewed items remain in the original
source pool. Advisory failures do not change collection completeness or risk scores.
Set `OSINT_LLM_REVIEW_ENABLED=false` to disable review. Review stages are not backfilled
into historical investigations. Network access to LM Studio is required from workers.

Review requests use LM Studio's schema-constrained JSON output, followed by local validation
of allowed labels, actual passage IDs and supplied links. Schema-valid output is still an
advisory interpretation, not proof of relevance. API format reference:
https://lmstudio.ai/docs/developer/openai-compat/structured-output

The [relevance benchmark](benchmarks/README.md) contains 30 labelled synthetic cases and an
optional bounded live runner. Its scores expose specific failure modes, not production
accuracy. Add independently labelled real examples and a held-out set before model tuning.
