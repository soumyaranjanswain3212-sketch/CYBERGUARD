# CyberGuard

CyberGuard is a student-built cybersecurity monitoring prototype for **authorized demonstrations and training**. It brings phishing, impersonation reports, suspicious URLs, and abnormal sign-in activity into one explainable dashboard.

> **Honest scope:** The current detector is a transparent, deterministic rule-based baseline. It is not a trained machine-learning model, a production security control, a malware sandbox, or a deepfake detector. A media report can be triaged, but confirming manipulated audio/video needs dedicated models and human review. Do not use prototype scores to make high-impact decisions.

## What works in this prototype

- Analyze email/message text, a URL, an identity/media concern, or sign-in signals.
- Classify signals into credential phishing, suspicious URL, impersonation/deepfake concern, or account takeover.
- Return a 0–100 heuristic risk score, severity, matched indicators, explanation, and suggested next actions.
- Browse incidents created by analysis requests and persisted in SQLite; search and filter them, inspect evidence, and update incident status.
- View event totals, hourly activity, category breakdown, and recent analyses, all derived from the API's persisted event records.
- Run the API and UI locally with separate development servers.

## Start locally

Requirements: Node.js 20+ and Python 3.10+.

In a terminal at the project root, install and start the frontend:

```powershell
npm install
npm run dev
```

In a second terminal, install and start the backend:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
python -m uvicorn backend.app.main:app --reload --port 8000
```

Open `http://localhost:5173`. The API is documented at `http://localhost:8000/docs`. The dashboard requires the API and displays no seeded or simulated incidents. Analysis events are stored in SQLite at `backend/cyberguard.sqlite3` by default; set `CYBERGUARD_DB_PATH` to choose another location.

Optional: set `VITE_API_BASE_URL` for a different API origin and `CYBERGUARD_CORS_ORIGINS` to a comma-separated list of trusted frontend origins. Never expose the development server or allow wildcard CORS on a public deployment.

## Authorized telemetry ingestion

`POST /api/ingest` accepts a normalized event from an authorized firewall, EDR, or application/API feed. The sender must map its event into the contract below; this endpoint does not connect to or fetch data from a vendor by itself.

Configure a high-entropy `CYBERGUARD_INGEST_TOKEN` in the API server's secret manager or process environment. Tokens shorter than 32 characters disable ingestion. Send it as an `Authorization: Bearer <token>` header. Generate a token locally with `python -c "import secrets; print(secrets.token_urlsafe(48))"`; do not commit it or paste it into chat. The development API uses localhost by default. For a remote event sender, put the API behind a TLS reverse proxy and firewall that allows only the authorized sender; do not expose the development server directly to the internet.

Required fields are `source` (`network`, `auth`, `email`, `identity`, or `url`), `source_name` (the trusted integration label), `source_event_id` (stable ID from the sender), and timezone-aware `observed_at`. Other accepted fields are the same validated analysis fields used by `/api/analyze`. Network measurements include `requests_per_minute` with `baseline_requests_per_minute`, `bytes_out_mb` with `baseline_bytes_out_mb`, and/or `error_rate_percent`. A value/baseline pair must be supplied together. Unknown fields are rejected. Repeated delivery of the same source name and event ID is idempotent; the external event ID is hashed for the stored CyberGuard ID and the raw webhook payload is not retained.

The endpoint returns HTTP 202 and the persisted analysis event. It reports a risk assessment, not an automatic block or containment action. Provider-specific field mapping, sender-side retries, time synchronization, and delivery monitoring must be configured and tested with the actual authorized feed before operational use.

### Cloudflare Logpush

`POST /api/ingest/cloudflare/logpush` accepts Cloudflare's gzipped NDJSON `firewall_events` batches directly. See Cloudflare's [HTTP destination requirements](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/http/). Configure the Logpush zone job with destination `https://<your-host>/api/ingest/cloudflare/logpush`, and add `header_Authorization=Bearer%20<URL-encoded-token>` to `destination_conf`. Select `Action` and `Datetime`; useful optional fields are `RayID`, `Source`, `Description`, `ClientRequestHost`, `ClientRequestMethod`, and `ClientIPClass`. Keep NDJSON output and RFC3339 timestamps. Set `max_upload_bytes` to 5,000,000 or greater; the receiver bounds decompressed batches to 5 MiB. The HTTPS endpoint must have a trusted certificate and be reachable by Cloudflare; restrict access using Cloudflare's current IP ranges and your TLS/reverse-proxy policy.

The Cloudflare route validates the bearer secret, gzip stream, NDJSON records, `Action`, and `Datetime` before analyzing and transactionally saving a batch. Cloudflare's documented gzipped `{"content":"tests"}` destination-validation probe is acknowledged without creating an incident. Repeated identical records are deduplicated. Client IP addresses and raw request bodies are not saved; the dashboard gets action, rule, request-target, and Ray ID evidence for analyst review. Scores reflect Cloudflare's reported firewall action and related signals; they are triage indicators, not proof of compromise or automatic response. A Logpush job and a stable public HTTPS endpoint still need to be configured before actual events will arrive.

## Detection method and scoring

The backend applies readable keyword and URL-structure checks—urgency, credential requests, authority references, payment requests, shortened/punycode/multi-hyphen/IP-literal or long domains, plus failed logins, unfamiliar devices, and unusual locations. For network/API reports, request or outbound-data volume at 2x, 3x, and 10x the supplied baseline adds increasing risk; API error rates at 25% and 50% also add risk. Those thresholds are configurable in code and are not learned from observed traffic. Indicator weights are added and capped at 100. Severity bands are Safe (0–14), Low (15–39), Medium (40–64), High (65–84), and Critical (85–100).

The service returns the evidence that contributed to its score. Some message rules overlap intentionally, so this score is a triage signal, not a calibrated probability. No email headers, DNS/WHOIS, browser redirects, image/audio/video bytes, threat-intelligence feeds, or user baselines are fetched or analyzed. Dashboard counters and charts are calculated from records in the configured SQLite database; an empty database produces an empty dashboard.

## Architecture

```text
Analyst
  │
  ▼
React + TypeScript dashboard (search, filters, event triage)
  │ HTTP / JSON, localhost:8000
  ▼
FastAPI API ── Pydantic input validation
  │
  ├── Authenticated normalized-event and Cloudflare Logpush ingestion
  ├── Rule-based signal extraction (text, URL shape, auth flags)
  ├── Weighted heuristic scoring + severity bands
  ├── Explanation, indicators, recommended actions
  └── Transactional, deduplicated SQLite event storage
```

The dashboard polls the API every 30 seconds. Cloudflare Logpush ingestion is implemented, but it will show no Cloudflare events until a `firewall_events` job is configured to send to a stable HTTPS endpoint with the same secret. Analysis requests and incident status changes are persisted in SQLite. Ingestion authentication does not protect the dashboard read/status endpoints; keep the complete API on a trusted local/VPN network or put it behind an authenticated reverse proxy. Production deployment still needs role-based access, audit logs, rate limiting, privacy controls, managed database backups, and monitoring.

## Evaluation and limitations

Run the focused detector tests:

```powershell
python -m unittest backend.tests.test_analyzer backend.tests.test_storage backend.tests.test_ingest_api backend.tests.test_cloudflare_ingest -v
```

The tests verify the expected classes, evidence, recommendations, safe-input caveat, and score cap against synthetic examples. They are functional checks, **not** an accuracy benchmark. No labeled external dataset or measured precision/recall/F1/latency is included; claiming those metrics would be misleading. For a defensible evaluation, obtain an appropriately licensed dataset, split it by source/time to prevent leakage, set a documented threshold, and report confusion matrix, precision, recall, F1, false-positive rate, and inference latency.

## Next steps for a research-grade system

1. Add a consented/labeled dataset and compare the rules baseline with a calibrated text classifier.
2. Add safe URL reputation/redirect analysis with SSRF protections and a sandboxed fetch service.
3. Configure and test a provider-specific adapter to the authenticated webhook contract and establish per-user/device behavioral baselines.
4. Evaluate dedicated audio/video deepfake models on licensed benchmarks; retain human review and uncertainty.
5. Add role-based access, durable incident workflows, auditability, deployment hardening, and privacy retention policies.

## GitHub

Source repository: [soumyaranjanswain3212-sketch/CYBERGUARD](https://github.com/soumyaranjanswain3212-sketch/CYBERGUARD).
