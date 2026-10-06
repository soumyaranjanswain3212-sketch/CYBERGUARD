# CyberGuard

CyberGuard is a student-built cybersecurity monitoring prototype for **authorized demonstrations and training**. It brings phishing, impersonation reports, suspicious URLs, and abnormal sign-in activity into one explainable dashboard.

> **Honest scope:** URL analysis now includes a locally trained URL-only classifier plus explainable rules. Message, identity, authentication, network, and Cloudflare assessments still use deterministic rules/telemetry; they are not trained detectors. CyberGuard does not detect deepfakes, fetch websites, run a malware sandbox, or automatically block/contain events. Scores are triage signals, not calibrated probabilities or proof of compromise. Keep a human reviewer in the loop.

## What works in this prototype

- Analyze email/message text, a URL, an identity/media concern, or sign-in signals.
- Classify signals into credential phishing, suspicious URL, impersonation/deepfake concern, or account takeover.
- Return a 0–100 heuristic risk score, severity, matched indicators, explanation, and suggested next actions.
- Score a URL with a locally trained logistic-regression classifier when its committed model artifact is installed; inference derives features from the URL string and never visits the destination.
- Browse incidents created by analysis requests and persisted in SQLite; search and filter them, inspect evidence, and update incident status.
- View event totals, hourly activity, category breakdown, and recent analyses, all derived from the API's persisted event records.
- Sign in to the analyst dashboard with a salted-password-hash account and a short-lived, CSRF-protected session.
- Run the API and UI locally with separate development servers.

## Start locally

Requirements: Node.js 20+ and Python 3.11+.

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
Copy-Item .env.example .env
python -m backend.scripts.set_analyst_password
```

Copy the password hash printed by the last command into `CYBERGUARD_ANALYST_PASSWORD_HASH` in `.env`. Replace `CYBERGUARD_SESSION_SECRET` and `CYBERGUARD_INGEST_TOKEN` with separate random values; generate each locally with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Do not put real secrets in source control, chat, screenshots, or logs. `.env` is ignored by Git.

Start the backend in the second terminal:

```powershell
python -m uvicorn backend.app.main:app --reload --port 8000 --env-file .env
```

Open `http://localhost:5173` and sign in using the username in `.env` and the password entered into the password-hash tool. The API is documented at `http://localhost:8000/docs`. The dashboard requires the API and displays no seeded or simulated incidents. Analysis events are stored in SQLite at `backend/cyberguard.sqlite3` by default; set `CYBERGUARD_DB_PATH` to choose another location.

Optional: set `VITE_API_BASE_URL` for a different API origin and `CYBERGUARD_CORS_ORIGINS` to a comma-separated list of trusted frontend origins. For a production deployment, set `CYBERGUARD_COOKIE_SECURE=true`, use HTTPS, and serve the UI/API on the same site behind an authenticated TLS reverse proxy. Never expose the development server or allow wildcard CORS on a public deployment.

### Analyst authentication

The event-list, dashboard-summary, status-update, and manual-analysis APIs require the configured analyst session. The starter configuration supports one shared analyst account (not per-person roles). Passwords are stored as salted PBKDF2-SHA256 hashes; sessions are signed, HTTP-only, SameSite=Strict cookies with an eight-hour expiry, and state-changing browser requests require a CSRF token. Five failed sign-ins lock the account for five minutes per API worker. For multiple workers or public deployments, configure shared rate limiting at the reverse proxy; this in-process limit is not a distributed control. The health endpoint remains public and reports only whether authentication is configured.

Run backend tests after installing `backend\requirements.txt`:

```powershell
python -m unittest backend.tests.test_auth backend.tests.test_analyzer backend.tests.test_storage backend.tests.test_ingest_api backend.tests.test_cloudflare_ingest backend.tests.test_url_model -v
```

Build-check the dashboard with `npm run build`.

## Authorized telemetry ingestion

`POST /api/ingest` accepts a normalized event from an authorized firewall, EDR, or application/API feed. The sender must map its event into the contract below; this endpoint does not connect to or fetch data from a vendor by itself.

Configure a high-entropy `CYBERGUARD_INGEST_TOKEN` in the API server's secret manager or process environment. Tokens shorter than 32 characters disable ingestion. Send it as an `Authorization: Bearer <token>` header. Generate a token locally with `python -c "import secrets; print(secrets.token_urlsafe(48))"`; do not commit it or paste it into chat. The development API uses localhost by default. For a remote event sender, put the API behind a TLS reverse proxy and firewall that allows only the authorized sender; do not expose the development server directly to the internet.

Required fields are `source` (`network`, `auth`, `email`, `identity`, or `url`), `source_name` (the trusted integration label), `source_event_id` (stable ID from the sender), and timezone-aware `observed_at`. Other accepted fields are the same validated analysis fields used by `/api/analyze`. Network measurements include `requests_per_minute` with `baseline_requests_per_minute`, `bytes_out_mb` with `baseline_bytes_out_mb`, and/or `error_rate_percent`. A value/baseline pair must be supplied together. Unknown fields are rejected. Repeated delivery of the same source name and event ID is idempotent; the external event ID is hashed for the stored CyberGuard ID and the raw webhook payload is not retained.

The endpoint returns HTTP 202 and the persisted analysis event. It reports a risk assessment, not an automatic block or containment action. Provider-specific field mapping, sender-side retries, time synchronization, and delivery monitoring must be configured and tested with the actual authorized feed before operational use.

The browser dashboard endpoints use the separate analyst session described above. Telemetry integrations use the bearer ingestion secret; they do not receive an analyst cookie.

### Cloudflare Logpush

`POST /api/ingest/cloudflare/logpush` accepts Cloudflare's gzipped NDJSON `firewall_events` batches directly. See Cloudflare's [HTTP destination requirements](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/http/). Configure the Logpush zone job with destination `https://<your-host>/api/ingest/cloudflare/logpush`, and add `header_Authorization=Bearer%20<URL-encoded-token>` to `destination_conf`. Select `Action` and `Datetime`; useful optional fields are `RayID`, `Source`, `Description`, `ClientRequestHost`, `ClientRequestMethod`, and `ClientIPClass`. Keep NDJSON output and RFC3339 timestamps. Set `max_upload_bytes` to 5,000,000 or greater; the receiver bounds decompressed batches to 5 MiB. The HTTPS endpoint must have a trusted certificate and be reachable by Cloudflare; restrict access using Cloudflare's current IP ranges and your TLS/reverse-proxy policy.

The Cloudflare route validates the bearer secret, gzip stream, NDJSON records, `Action`, and `Datetime` before analyzing and transactionally saving a batch. Cloudflare's documented gzipped `{"content":"tests"}` destination-validation probe is acknowledged without creating an incident. Repeated identical records are deduplicated. Client IP addresses and raw request bodies are not saved; the dashboard gets action, rule, request-target, and Ray ID evidence for analyst review. Scores reflect Cloudflare's reported firewall action and related signals; they are triage indicators, not proof of compromise or automatic response. A Logpush job and a stable public HTTPS endpoint still need to be configured before actual events will arrive.

## Detection method and scoring

The backend applies readable keyword and URL-structure checks—urgency, credential requests, authority references, payment requests, shortened/punycode/multi-hyphen/IP-literal or long domains, plus failed logins, unfamiliar devices, and unusual locations. When the trained artifact is present, a Logistic Regression model adds a URL-only signal using URL length, host/path/query structure, character ratios, entropy, and suspicious lexical indicators. It does not resolve DNS or open the page. For network/API reports, request or outbound-data volume at 2x, 3x, and 10x the supplied baseline adds increasing risk; API error rates at 25% and 50% also add risk. Those thresholds are configurable in code and are not learned from observed traffic. Indicator weights are added and capped at 100. Severity bands are Safe (0–14), Low (15–39), Medium (40–64), High (65–84), and Critical (85–100).

The service returns the evidence that contributed to its score. Model scores are not calibrated probabilities; the combined event score is not a probability either. No email headers, DNS/WHOIS, browser redirects, image/audio/video bytes, threat-intelligence feeds, or learned user baselines are fetched or analyzed. Dashboard counters and charts are calculated from records in the configured SQLite database; an empty database produces an empty dashboard.

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
  ├── URL-only Logistic Regression model + rule-based text/auth/network assessment
  ├── Authenticated normalized-event and Cloudflare Logpush ingestion
  ├── Evidence-based explanations + weighted risk scoring
  ├── Explanation, indicators, recommended actions
  └── Transactional, deduplicated SQLite event storage
```

The dashboard polls the API every 30 seconds and requires an analyst session. The health endpoint reports if the URL model is loaded. Cloudflare Logpush ingestion is implemented, but it will show no Cloudflare events until a `firewall_events` job is configured to send to a stable HTTPS endpoint with the same secret. Analysis requests and incident status changes are persisted in SQLite. The current login is one configured shared analyst account; it does not provide individual users, role-based permissions, or a durable audit log. Production deployment still needs identity-provider integration, shared rate limiting, privacy controls, managed database backups, and monitoring.

## URL model dataset, evaluation, and limitations

The committed URL-only model was trained from the [UCI PhiUSIIL Phishing URL (Website) dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), UCI ID 967, under its **CC BY 4.0** license. The dataset contains 235,795 labeled records; its documented target mapping is `0 = phishing` and `1 = legitimate`. The model uses only features derived from `URL`, not the webpage-derived columns. The 56 MB source CSV is downloaded to the Git-ignored `backend/data/phiusiil.csv` and is not included in this repository. Dataset citation: Prasad & Chandra (2023), “PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning,” *Computers & Security*, 103545, [doi:10.1016/j.cose.2023.103545](https://doi.org/10.1016/j.cose.2023.103545). The exact training CSV SHA-256 is recorded in the model report.

Training and threshold selection are reproducible:

```powershell
python -m backend.scripts.train_url_model
```

If the CSV is absent, the command downloads it from the official UCI `data.csv` endpoint, writes the local model parameters as non-executable JSON to `backend/models/phiusiil_url_model.json`, and records metrics/provenance in `backend/models/phiusiil_url_model.metrics.json`. The runtime reads and validates the JSON parameters and computes the logistic score directly; it does not unpickle or execute model code. `GroupShuffleSplit` holds out exact UCI `Domain` values: 165,590 training rows, 23,484 validation rows, and 46,721 test rows. The operating threshold is the lowest validation threshold of at least 0.50 that keeps the validation false-positive rate at or below 0.1%; the test set remains held out. This conservative operating point was chosen after a benign-domain regression check exposed false positives at the previous F1-maximizing threshold. That small smoke check is not an accuracy benchmark or a domain allowlist. This is a within-dataset, domain-grouped evaluation—not an independent temporal or cross-provider benchmark.

Measured on the held-out UCI test split on this development machine:

| Metric | Result |
|---|---:|
| Accuracy | 98.79% |
| Precision | 99.83% |
| Recall | 97.32% |
| F1 | 98.56% |
| ROC AUC | 99.68% |
| Average precision | 99.72% |
| Validation false-positive rate | 0.09% (12/13,506 legitimate URLs) |
| Held-out test false-positive rate | 0.12% (32/26,923 legitimate URLs) |
| Confusion matrix | TN 26,891 · FP 32 · FN 531 · TP 19,267 |
| URL feature + model inference latency | p50 0.66 ms · p95 1.33 ms, 1,000 single-URL samples |

The latency figure is local CPU feature extraction plus model inference; it excludes HTTP, hosting, and network time. The classifier's percentage-like score is not calibrated probability. Strong benchmark performance does not guarantee future detection: dataset provenance, domain grouping, out-of-distribution URLs, label quality, concept drift, and provider-specific traffic can change results. Review the included metrics JSON and rerun evaluation on a separately licensed, later dataset before operational use. Other threat categories have no measured classifier accuracy.

The test suite also includes a handful of known benign-domain smoke checks to guard against the reported false-positive regression; these are not a representative benign-domain benchmark and are not included in the performance figures. Other synthetic unit tests check predictable API behavior and are not presented as model-performance evidence.

Run backend tests:

```powershell
python -m unittest backend.tests.test_auth backend.tests.test_analyzer backend.tests.test_storage backend.tests.test_ingest_api backend.tests.test_cloudflare_ingest backend.tests.test_url_model -v
```

Build-check the dashboard with `npm run build`.

## Next steps for a research-grade system

1. Deploy to a stable HTTPS host, configure the Cloudflare `firewall_events` Logpush job, and verify real delivery in the dashboard.
2. Integrate authenticated feeds from the actual email, identity, endpoint, or API providers used by the organization.
3. Select and evaluate appropriately licensed audio/video/image deepfake models and benchmarks; this release does not detect manipulated media.
4. Add individually attributable user accounts, role-based permissions, durable audit logs, shared rate limiting, backups, retention controls, and monitoring.
5. Run temporal and cross-provider phishing evaluations and monitor drift before using the model to guide operational action.

## GitHub

Source repository: [soumyaranjanswain3212-sketch/CYBERGUARD](https://github.com/soumyaranjanswain3212-sketch/CYBERGUARD).
