# Web Investigator

Web Investigator combines dynamic Playwright-based evidence collection with a passive Web Intelligence and OSINT workspace.

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
- Keyless public RSS search collection, with optional Brave Search API support
- Search-result URL normalization and deduplication
- Source classification and query-to-source traceability
- Bounded public-result collection with manual-required logging for protected pages
- Query-derived, case-insensitive evidence matching on public SERP result pages
- DOM-safe keyword highlighting and bounded Playwright viewport screenshots
- Screenshot SHA-256 provenance, surrounding text, source rank, and query linkage
- Evidence gallery and self-contained evidence screenshots in HTML reports
- Structured SQLite persistence with evidence hashes
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

Without these credentials, reports show `Unavailable`. Cached traffic values are reused unless **Refresh traffic data** is selected in the Resolution tab.

Brand and partial-name resolution uses the keyless provider when Brave is not configured. Complete URLs and domains resolve locally without any search request.

Run the application:

```bash
.venv/bin/streamlit run app.py
```

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
