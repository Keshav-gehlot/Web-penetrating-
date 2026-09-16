# PHANTOM Security Platform

PHANTOM is an authorized security-assessment platform with a React/Vite operator console and a FastAPI assessment API.

## Current implementation

- 25 registered assessment modules
- Concurrent scan runner with bounded timeouts
- Target validation that blocks local/private/reserved destinations by default
- DNS and subdomain discovery
- Bounded common-port discovery
- HTTP security-header analysis
- TLS certificate/protocol inspection
- Cookie and CORS auditing
- WAF and technology fingerprinting
- Endpoint/form inventory
- Candidate SQLi/XSS/CSRF/SSRF/XXE/open-redirect detection without destructive exploit payloads
- RDAP domain/IP enrichment
- NVD CVE keyword enrichment from exposed software metadata
- Background scan execution through FastAPI BackgroundTasks
- JSON-normalized scan results
- PDF assessment report generation

## Run the API

```bash
cd backend
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

API documentation is available at `/docs` when the server is running.

## Scan example

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com","profile":"quick"}'
```

Use the returned scan ID with `GET /api/v1/scans/{scan_id}`. A PDF is available at `/api/v1/reports/{scan_id}.pdf` after the scan completes.

## Safety boundary

PHANTOM is designed for systems the operator owns or is explicitly authorized to assess. The baseline engine uses bounded, non-destructive checks. Intrusive exploit verification should be implemented only as a separately controlled workflow with explicit scope, rate limits, logging, and approval.

## Frontend

The existing React/Vite frontend remains the operator-console layer. The next integration step is replacing its demo state with these API endpoints and real scan events.
