# PHANTOM Security Platform

PHANTOM is an original, workspace-scoped security assessment platform built for authorized testing. It combines a React/Vite operator console with a FastAPI API, PostgreSQL persistence, Redis Streams job orchestration, and a native Python worker.

## Architecture

```text
React / Vite :5173
      │ HTTPS / WebSocket
      ▼
FastAPI :8000
 ├── Auth + RBAC
 ├── Assets / Scans / Findings
 ├── Investigation / Reports / Audit
 ├── Workspace Team Management
 └── Health / Readiness / System Status
      │
      ├───────────────┐
      ▼               ▼
PostgreSQL :5432   Redis :6379
                       │
                       ▼
                 Redis Streams
                       │
                       ▼
                Native PHANTOM Worker
```

Docker is not required or used by the project.

## Local setup

Start PostgreSQL and Redis natively, then:

```bash
cd backend
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

In another terminal, from `backend`:

```bash
python -m app.worker
```

Then from the repository root:

```bash
npm install
npm run dev
```

The operator console runs on `http://127.0.0.1:5173` and the API on `http://localhost:8000`.

## Database and migrations

Alembic owns schema changes. Run `alembic upgrade head` before starting the API against a new database. Application startup performs bootstrap data creation only; it does not mutate table definitions.

## Authentication and access control

PHANTOM uses signed bearer sessions with server-side membership validation and role enforcement. WebSocket scan updates use dedicated, short-lived, single-use tickets scoped to a specific scan and workspace.

The default development bootstrap values come from environment variables. Replace `PHANTOM_AUTH_SECRET` and `PHANTOM_BOOTSTRAP_PASSWORD` before using PHANTOM outside local development.

## Scan execution and reliability

Scan jobs use Redis Streams consumer groups with acknowledgement and stale-message recovery. Workers claim scans atomically in PostgreSQL, maintain renewable execution leases, use a distributed concurrency pool, and retry bounded failures up to the configured attempt limit.

Scanner modules use bounded module/total timeouts, per-scan request budgets, redirect caps, response-size limits, and DNS checks that reject non-public destinations by default.

## Operator console

The console includes authenticated dashboard, asset inventory, scan execution/live events, vulnerabilities, investigation, reports, topology, OSINT source directory, audit logs, team/roles, settings, and a safe operations terminal view. User-visible pages are backed by persisted PHANTOM data rather than demo security findings or fabricated infrastructure.

## Implemented assessment coverage

PHANTOM currently includes bounded discovery, DNS/subdomain checks, common-port checks, HTTP/TLS/header analysis, cookie and CORS auditing, WAF/technology detection, endpoint/form inventory, trust auditing, RDAP/CVE enrichment, and candidate SQLi/XSS/CSRF/SSRF/XXE/open-redirect signals without destructive exploit automation.

## CI

GitHub Actions validates Python compilation, the Alembic migration graph, backend unit tests, TypeScript compilation, and the production frontend build on `main` and `phantom-v2`.

## Security boundary

Use PHANTOM only against systems you own or have explicit authorization to assess. The baseline scanner intentionally avoids unrestricted exploit execution and keeps network activity bounded.
