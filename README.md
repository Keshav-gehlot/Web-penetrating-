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
 └── Health / Readiness
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

## Database

Alembic owns schema changes. Run `alembic upgrade head` before starting the API against a new database. Application startup performs bootstrap data creation only; it does not mutate table definitions.

## Authentication

The default development bootstrap values come from environment variables. Change `PHANTOM_AUTH_SECRET` and `PHANTOM_BOOTSTRAP_PASSWORD` before using PHANTOM outside local development.

## Scan controls

The worker uses Redis Streams consumer groups with acknowledgement and stale-message recovery. Scan execution uses database worker ownership, renewable leases, bounded module/total timeouts, retry attempts, and a distributed scan-concurrency slot pool.

Targets are validated before execution. Private, local, loopback, link-local, multicast, and reserved destinations are rejected by default.

## Implemented assessment coverage

PHANTOM currently includes bounded discovery, DNS/subdomain checks, common-port checks, HTTP/TLS/header analysis, cookie and CORS auditing, WAF/technology detection, endpoint/form inventory, trust auditing, RDAP/CVE enrichment, and candidate SQLi/XSS/CSRF/SSRF/XXE/open-redirect signals without destructive exploit automation.

## Security boundary

Use PHANTOM only against systems you own or have explicit authorization to assess. The baseline scanner intentionally avoids unrestricted exploit execution and keeps network activity bounded.
