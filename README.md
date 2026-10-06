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

## Detection method and scoring

The backend applies readable keyword and URL-structure checks—urgency, credential requests, authority references, payment requests, shortened/punycode/multi-hyphen/IP-literal or long domains, plus failed logins, unfamiliar devices, and unusual locations. For network/API reports, request or outbound-data volume at 2x, 3x, and 10x the supplied baseline adds increasing risk; API error rates at 25% and 50% also add risk. Those thresholds are configurable in code and are not learned from observed traffic. Indicator weights are added and capped at 95. Severity bands are Safe (0–14), Low (15–39), Medium (40–64), High (65–84), and Critical (85–95).

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
  ├── Rule-based signal extraction (text, URL shape, auth flags)
  ├── Weighted heuristic scoring + severity bands
  └── Explanation, indicators, recommended actions
```

The dashboard polls the API every 30 seconds; this is not a connection to external mail, identity, endpoint, or network telemetry sources. Analysis requests and incident status changes are persisted in SQLite. The backend can be containerized behind a TLS-terminating reverse proxy; production deployment would still need authenticated ingestion, authorization, audit logs, rate limiting, secrets management, privacy controls, managed database backups, and monitoring. The API must remain on a trusted network until those controls are implemented.

## Evaluation and limitations

Run the focused detector tests:

```powershell
python -m unittest backend.tests.test_analyzer -v
```

The tests verify the expected classes, evidence, recommendations, safe-input caveat, and score cap against synthetic examples. They are functional checks, **not** an accuracy benchmark. No labeled external dataset or measured precision/recall/F1/latency is included; claiming those metrics would be misleading. For a defensible evaluation, obtain an appropriately licensed dataset, split it by source/time to prevent leakage, set a documented threshold, and report confusion matrix, precision, recall, F1, false-positive rate, and inference latency.

## Next steps for a research-grade system

1. Add a consented/labeled dataset and compare the rules baseline with a calibrated text classifier.
2. Add safe URL reputation/redirect analysis with SSRF protections and a sandboxed fetch service.
3. Add authenticated log ingestion and per-user/device behavioral baselines.
4. Evaluate dedicated audio/video deepfake models on licensed benchmarks; retain human review and uncertainty.
5. Add role-based access, durable incident workflows, auditability, deployment hardening, and privacy retention policies.

## GitHub

The current workspace has no Git remote configured. To connect and publish it, create a GitHub repository and provide its repository URL; publishing also requires GitHub authentication in your local Git tooling. Do not put access tokens in project files or chat.
