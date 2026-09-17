# PHANTOM Security Platform

PHANTOM is an enterprise-oriented security assessment and cybersecurity operations platform for authorized security testing. It provides a workspace-scoped operator console, controlled scan execution, finding management, investigation workflows, reporting, auditability, real-time scan visibility, and native endpoint network observability.

> **Security boundary:** Use PHANTOM only against systems you own or have explicit authorization to assess. The platform is designed around bounded, non-destructive assessment workflows and does not provide unrestricted exploit automation.

## Architecture

```text
React / TypeScript / Vite
          │
     HTTPS / WebSocket
          ▼
     FastAPI application
          │
   ┌──────┼───────────────┐
   ▼      ▼               ▼
PostgreSQL Redis     Network Monitor
   │      │            (native psutil)
   │      │               │
   │      ▼               │
   │  Redis Streams       │
   │      │               │
   │      ▼               │
   │ Native PHANTOM Worker│
   │      │               │
   └──────┼───────────────┘
          ▼
     Scan modules
          │
          ▼
 Result normalization
          │
          ▼
 Findings + Evidence
          │
 Reports / Remediation
```

## Backend

The backend is a native Python service built with FastAPI and asynchronous SQLAlchemy. It is separated into API, persistence, authentication, authorization, scope validation, scanner runtime, queue, real-time event, worker, and network-observability layers.

### Backend capabilities

- FastAPI REST API with OpenAPI documentation in development
- Async SQLAlchemy + PostgreSQL
- Alembic-managed schema migrations
- Redis Streams consumer groups for durable scan jobs
- Native asynchronous scan worker; **Docker is not required or used**
- Workspace-scoped authorization on server-side queries
- Signed bearer sessions with server-side membership revalidation
- One-time, short-lived WebSocket tickets scoped to a scan/workspace
- Request IDs, security response headers, and structured request logging
- Liveness and dependency readiness endpoints
- Worker leases, heartbeats, retry limits, stale-job recovery, and global scan concurrency control
- Bounded scanner execution with module and total timeouts
- Per-scan request budgets, redirect limits, response-size limits, and public-target protections
- Audit events for security-sensitive operations
- Controlled, non-destructive assessment modules
- Native endpoint network visibility without an IPC/socket traffic daemon

## Runtime

| Component | Default address |
|---|---|
| React/Vite console | `http://127.0.0.1:5173` |
| FastAPI API | `http://localhost:8000` |
| PostgreSQL | `localhost:5432` |
| Redis | `localhost:6379` |

## Technology stack

### Frontend

- React
- TypeScript
- Vite
- Tailwind CSS
- Motion
- React Router
- Recharts
- Lucide icons

### Backend

- Python 3.11+
- FastAPI
- Pydantic
- SQLAlchemy 2.x
- asyncpg
- PostgreSQL
- Redis Streams
- Alembic
- httpx
- psutil
- ReportLab
- pytest / pytest-asyncio

## Local development

### Prerequisites

Install:

- Node.js 22+
- Python 3.11+
- PostgreSQL
- Redis

Create a PostgreSQL database named `phantom` and make sure PostgreSQL and Redis are running locally.

### Configure environment

Copy `.env.example` to `.env` and replace development secrets as appropriate.

```text
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/phantom
PHANTOM_REDIS_URL=redis://localhost:6379/0
PHANTOM_CORS_ORIGINS=http://localhost:5173
PHANTOM_AUTH_SECRET=<long-random-secret>
PHANTOM_BOOTSTRAP_EMAIL=admin@phantom.local
PHANTOM_BOOTSTRAP_PASSWORD=<strong-development-password>
```

On Windows, create `.env` manually if `cp` is unavailable.

### Backend setup

```bash
cd backend
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install and migrate:

```bash
pip install -r requirements.txt
alembic upgrade head
```

Start the API:

```bash
uvicorn app.main:app --reload --port 8000
```

Start the worker in a second terminal:

```bash
cd backend
.venv\Scripts\activate
python -m app.worker
```

Use `source .venv/bin/activate` instead on Linux/macOS.

### Frontend setup

From the repository root:

```bash
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

## API health

Liveness:

```text
GET /health
```

Dependency readiness:

```text
GET /ready
```

`/ready` returns HTTP 503 when PostgreSQL or Redis is unavailable.

Development API documentation is available at `/docs` and `/redoc`. These documentation endpoints are disabled when `PHANTOM_ENV=production`.

## Network observability

PHANTOM now includes a native Python network-observability layer based on `psutil`. It does **not** require a separate packet-capture daemon, Unix socket, named pipe, or Docker service.

The monitor provides:

- active TCP/UDP connection inventory;
- listening-service visibility;
- owning PID/process name where the OS permits access;
- executable-path context where permitted;
- first-seen tracking for new connections;
- sensitive-service port risk signals;
- external exposure signals for selected sensitive services;
- process executable path checks for temporary/download locations;
- total network I/O counters;
- per-interface I/O counters;
- send/receive bytes-per-second measurements;
- VPN/tunnel-like interface detection;
- bounded in-memory connection history.

Endpoints:

```text
GET /api/v1/network/snapshot
GET /api/v1/network/connections
GET /api/v1/network/interfaces
```

All three endpoints require the authenticated `scan:view` permission.

The monitor is intentionally an observability layer. It does not inject packets, manipulate traffic, perform packet replay, or automatically terminate connections.

## Authentication and authorization

PHANTOM uses signed bearer sessions. Every authenticated request revalidates the user and workspace membership against PostgreSQL, so a stale client-side role cannot grant access.

Roles:

- `OWNER`
- `ADMIN`
- `SECURITY_LEAD`
- `ANALYST`
- `DEVELOPER`
- `VIEWER`

Examples of protected permissions include `scan:create`, `scan:cancel`, `finding:assign`, `finding:close`, `report:export`, `users:manage`, and `audit:view`.

Real-time scan connections use a separate short-lived, single-use WebSocket ticket. The ticket is bound to the scan and workspace and membership is revalidated when the ticket is consumed.

## Scan execution

Scan jobs use Redis Streams consumer groups and native workers.

```text
API
 │ XADD
 ▼
Redis Stream
 │
 ▼
Consumer Group
 │
 ▼
PHANTOM Worker
 │
 ├── acquire execution slot
 ├── claim DB lease
 ├── execute bounded modules
 ├── refresh worker lease
 └── XACK / retry
```

The worker supports:

- atomic database scan claims;
- worker execution leases;
- worker heartbeats;
- stale lease recovery;
- Redis `XAUTOCLAIM` recovery;
- bounded retry attempts;
- global scan concurrency slots;
- module timeouts;
- total scan timeout;
- cancellation handling;
- duplicate-job protection.

## Scanner safety controls

Network assessment is deliberately bounded and non-destructive.

Controls include:

- public-target validation;
- private/loopback/link-local/multicast/reserved destination blocking;
- DNS revalidation before outbound HTTP requests;
- per-scan request budgets;
- connection and request timeouts;
- redirect limits;
- maximum response size;
- fixed common-port discovery set;
- small bounded directory enumeration set;
- harmless XSS reflection markers;
- database error-signature checks instead of injection payloads;
- candidate SSRF/XXE detection without exploit payloads;
- redirect-parameter identification without following external attack destinations.

## Current assessment coverage

The platform includes bounded checks for areas such as:

- asset and endpoint discovery;
- DNS and subdomain signals;
- common-port discovery;
- HTTP security headers;
- TLS configuration signals;
- cookie security attributes;
- CORS configuration;
- WAF and technology indicators;
- endpoint and form inventory;
- security/trust configuration;
- RDAP and software metadata enrichment;
- candidate SQL injection, XSS, CSRF, SSRF, XXE, and open-redirect signals.

These are assessment signals, not automatic proof of exploitability.

## Findings

Findings contain severity, CVSS/CWE/CVE metadata where available, evidence, confidence, ownership, remediation guidance, and scan history.

Lifecycle:

```text
OPEN → TRIAGED → ASSIGNED → IN REMEDIATION → FIXED → VERIFIED → CLOSED
```

Additional outcomes include `ACCEPTED RISK` and `FALSE POSITIVE`.

## Differential analysis

PHANTOM compares scans for the same workspace asset and identifies:

- new findings;
- resolved findings;
- persistent findings;
- severity regressions.

## Real-time operations

```text
Scanner
   ↓
PostgreSQL
   ↓
Redis Pub/Sub
   ↓
WebSocket
   ↓
Live Scan Console
```

Typical events include `scan.created`, `scan.started`, `module.started`, `module.progress`, `finding.created`, `module.completed`, `scan.completed`, `scan.failed`, and `scan.cancelled`.

## Reports

Reports are generated from persisted assessment data and can include:

1. Assessment metadata
2. Executive summary
3. Scope
4. Methodology
5. Risk overview
6. Findings
7. Evidence
8. Remediation
9. Technical appendix
10. Scan metadata

## Testing

Backend:

```bash
cd backend
pytest -q
python -m compileall -q app alembic tests
alembic history
alembic heads
```

Frontend:

```bash
npm run lint
npm run build
```

GitHub Actions runs the backend and frontend validation for **`phantom-v2`**, the project's PHANTOM development branch.

## Project structure

```text
.
├── backend/
│   ├── app/
│   │   ├── api/             # REST and WebSocket routes
│   │   ├── scanners/        # Bounded assessment modules/runtime
│   │   ├── auth.py          # Sessions and WS tickets
│   │   ├── database.py      # Async DB sessions/bootstrap
│   │   ├── middleware.py    # Request IDs/logging/security headers
│   │   ├── models.py        # SQLAlchemy models
│   │   ├── network_monitor.py# Native endpoint network observability
│   │   ├── queue.py         # Redis Streams
│   │   ├── rbac.py          # Roles and permissions
│   │   ├── realtime.py      # Scan event bus
│   │   ├── scan_guard.py    # Distributed scan concurrency
│   │   ├── security_scope.py# Target scope controls
│   │   └── worker.py        # Native scan worker
│   ├── alembic/             # Versioned database migrations
│   ├── tests/               # Backend tests
│   └── requirements.txt
├── src/
│   ├── components/          # Console UI
│   ├── lib/                 # API/auth utilities
│   └── pages/               # Operator views
├── .env.example
├── package.json
└── README.md
```

## Branch

PHANTOM development is maintained on:

```text
phantom-v2
```

No additional PHANTOM development branch is required.

## Originality and dependencies

The requested source repository is owned by you. I used it as a feature reference and did not copy its application code into PHANTOM. PHANTOM's application architecture, interface, terminology, workflows, and security logic remain developed specifically for this project.

Standard frameworks and libraries are used as dependencies and remain subject to their respective licenses and notices.

## License

A project license should be added before public distribution. Until then, repository contents should not be assumed to be freely reusable.

## Status

PHANTOM is under active development. Scanner coverage, integrations, network observability, and operational controls will continue to evolve as the platform is hardened.
