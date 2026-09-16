# PHANTOM Security Platform

PHANTOM is an enterprise-oriented security assessment and cybersecurity operations platform for authorized security testing. It provides a workspace-scoped operator console, controlled scan execution, finding management, investigation workflows, reporting, auditability, and real-time scan visibility.

> **Security boundary:** Use PHANTOM only against systems you own or have explicit authorization to assess. The platform is designed around bounded, non-destructive assessment workflows and does not provide unrestricted exploit automation.

## What PHANTOM provides

- **Workspace isolation** — assets, scans, findings, reports, and team activity are scoped to a workspace.
- **Authentication and RBAC** — server-side role and permission enforcement.
- **Asset inventory** — maintain the systems and targets being assessed.
- **Controlled scanning** — quick, standard, deep, and PHANTOM Trust assessment profiles.
- **Live scan operations** — real-time module progress, findings, status, and scan events.
- **Vulnerability management** — severity, CVSS/CWE/CVE metadata, evidence, assignment, remediation, and lifecycle tracking.
- **Investigation workspace** — correlate findings with evidence, timelines, requests/responses, notes, and remediation context.
- **Differential analysis** — identify new, resolved, persistent, and regressed findings between scans.
- **Reports** — generate structured technical and management-facing assessment reports.
- **Topology and discovery** — represent discovered assets, services, and relationships.
- **Audit logging** — record security-relevant workspace and administrative actions.
- **Team management** — workspace members and role administration.
- **Operational telemetry** — health, readiness, queue, worker, and system status visibility.

## Architecture

```text
                         PHANTOM Operator Console
                         React + TypeScript + Vite
                                   │
                            HTTPS / WebSocket
                                   │
                                   ▼
                         FastAPI Security API
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
              ▼                    ▼                    ▼
        PostgreSQL              Redis              API Services
          :5432                 :6379              Auth / RBAC
              │                    │                Assets / Scans
              │                    ▼                Findings / Reports
              │             Redis Streams           Audit / Team
              │                    │
              │                    ▼
              │          Native PHANTOM Worker
              │                    │
              │          ┌─────────┴─────────┐
              │          ▼                   ▼
              │    Discovery Modules   Assessment Modules
              │          │                   │
              └──────────┴───────────┬───────┘
                                     ▼
                             Result Normalizer
                                     │
                                     ▼
                           Findings + Evidence
                                     │
                                     ▼
                           Reports / Remediation
```

### Runtime

PHANTOM uses a native local/server runtime. **Docker is not required or used.**

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

- Python
- FastAPI
- SQLAlchemy
- PostgreSQL
- Redis Streams
- Native asynchronous worker
- Alembic migrations
- ReportLab for PDF reports

## Local development

### 1. Prerequisites

Install:

- Node.js
- Python 3.11+
- PostgreSQL
- Redis

Create a PostgreSQL database named `phantom` and make sure PostgreSQL and Redis are running locally.

### 2. Configure the backend

Copy the example environment file and replace the development secrets before using the platform outside a local development environment.

```bash
cp .env.example .env
```

At minimum, configure:

```text
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/phantom
PHANTOM_REDIS_URL=redis://localhost:6379/0
PHANTOM_CORS_ORIGINS=http://localhost:5173
PHANTOM_AUTH_SECRET=<long-random-secret>
PHANTOM_BOOTSTRAP_EMAIL=admin@phantom.local
PHANTOM_BOOTSTRAP_PASSWORD=<strong-development-password>
```

On Windows, create `.env` manually if `cp` is unavailable.

### 3. Install and migrate the backend

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

Then:

```bash
pip install -r requirements.txt
alembic upgrade head
```

### 4. Start the API

From `backend`:

```bash
uvicorn app.main:app --reload --port 8000
```

### 5. Start the worker

In another terminal:

```bash
cd backend
.venv\Scripts\activate
python -m app.worker
```

Use the equivalent `source .venv/bin/activate` command on Linux/macOS.

### 6. Start the frontend

From the repository root:

```bash
npm install
npm run dev
```

Open the console at:

```text
http://127.0.0.1:5173
```

## Database migrations

Alembic is the source of truth for database schema changes.

Apply migrations:

```bash
cd backend
alembic upgrade head
```

Create a migration during development when the SQLAlchemy models change:

```bash
alembic revision --autogenerate -m "describe the schema change"
```

Review generated migrations before applying them. Production deployments should run migrations explicitly rather than relying on application startup to alter database schemas.

## Authentication and authorization

PHANTOM uses signed bearer sessions and validates workspace membership on the server. Roles include:

- `OWNER`
- `ADMIN`
- `SECURITY_LEAD`
- `ANALYST`
- `DEVELOPER`
- `VIEWER`

Security-sensitive operations are protected by explicit permissions such as `scan:create`, `scan:cancel`, `finding:assign`, `finding:close`, `report:export`, `users:manage`, and `integrations:manage`.

Real-time scan updates use dedicated short-lived WebSocket tickets scoped to the requested scan and workspace.

## Scan execution

Scan jobs are delivered through **Redis Streams consumer groups** to native PHANTOM workers. The execution layer provides:

- bounded module execution timeouts;
- bounded total scan duration;
- per-scan request budgets;
- redirect limits;
- response-size limits;
- controlled concurrency;
- worker execution leases;
- retry limits;
- stale-job recovery;
- cancellation handling;
- structured scan events over WebSocket.

The scanner intentionally avoids unrestricted exploit execution. Assessment modules use bounded checks and normalize their results into PHANTOM findings.

## Assessment coverage

The current platform includes bounded checks for areas such as:

- target and asset discovery;
- DNS and subdomain signals;
- common-port discovery;
- HTTP security headers;
- TLS configuration signals;
- cookie security attributes;
- CORS configuration;
- WAF and technology indicators;
- endpoint and form inventory;
- trust/security configuration checks;
- RDAP and CVE enrichment;
- candidate SQL injection, XSS, CSRF, SSRF, XXE, and open-redirect signals.

These checks are intentionally constrained and non-destructive. A finding is an assessment signal that should be validated by an authorized security professional before remediation or escalation.

## Finding lifecycle

```text
OPEN
  ↓
TRIAGED
  ↓
ASSIGNED
  ↓
IN REMEDIATION
  ↓
FIXED
  ↓
VERIFIED
  ↓
CLOSED
```

Additional outcomes include `ACCEPTED RISK` and `FALSE POSITIVE`.

Findings can contain evidence, affected assets/endpoints, severity, CVSS/CWE/CVE metadata, timestamps, ownership, remediation guidance, and scan history.

## Real-time operations

The live scan workflow is:

```text
Scan created
    ↓
Redis Stream
    ↓
Native worker
    ↓
Scanner modules
    ↓
Normalized findings
    ↓
PostgreSQL persistence
    ↓
Redis Pub/Sub events
    ↓
WebSocket
    ↓
PHANTOM Live Scan console
```

Typical events include `scan.created`, `scan.started`, `module.started`, `module.progress`, `finding.created`, `module.completed`, `scan.completed`, `scan.failed`, and `scan.cancelled`.

## Reports

Reports are generated from persisted assessment data and can include:

1. Cover and assessment metadata
2. Executive summary
3. Scope
4. Methodology
5. Risk overview
6. Findings
7. Evidence
8. Remediation guidance
9. Technical appendix
10. Scan metadata

## Security principles

PHANTOM is designed around the following principles:

- **Authorization first** — assessment targets must be authorized.
- **Least privilege** — access is controlled by workspace membership and permissions.
- **Scope isolation** — cross-workspace resource access is rejected by the backend.
- **Bounded execution** — network activity has explicit limits and timeouts.
- **Auditability** — security-sensitive actions are recorded.
- **Safe defaults** — scanner modules avoid destructive exploit behavior.
- **Server-side enforcement** — client-provided role claims are never trusted for authorization.

## Testing and CI

Frontend type checking/build:

```bash
npm run lint
npm run build
```

Backend validation and tests are executed by the repository's GitHub Actions workflow. CI validates Python compilation, migration integrity, backend tests, TypeScript compilation, and the production frontend build.

## Project structure

```text
.
├── backend/
│   ├── app/
│   │   ├── api/          # HTTP API routes
│   │   ├── scanners/     # Bounded assessment modules
│   │   ├── auth.py       # Authentication
│   │   ├── database.py   # Database bootstrap/session handling
│   │   ├── models.py     # SQLAlchemy models
│   │   ├── queue.py      # Redis Streams queue
│   │   ├── rbac.py       # Permissions and roles
│   │   ├── realtime.py   # Scan event bus
│   │   └── worker.py     # Native scan worker
│   ├── alembic/          # Database migrations
│   └── requirements.txt
├── src/
│   ├── components/       # Console UI components
│   ├── lib/              # API/auth/client utilities
│   └── pages/            # PHANTOM operator views
├── .env.example
├── package.json
└── README.md
```

## Originality and dependencies

PHANTOM's application architecture, interface, terminology, workflows, and security logic are developed specifically for this project. The project does not present third-party proprietary or open-source application code as its own work.

PHANTOM uses standard frameworks and libraries as dependencies. Their respective licenses and notices remain applicable to those dependencies.

## License

A project license should be added here before public distribution. Until then, repository contents should not be assumed to be freely reusable.

## Status

PHANTOM is under active development. Features, scanner coverage, integrations, and operational controls may evolve as the platform is hardened.
