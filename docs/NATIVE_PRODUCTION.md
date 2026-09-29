# PHANTOM native production deployment (no Docker)

PHANTOM supports a native Linux deployment with Nginx, a Vite static build, Uvicorn, PostgreSQL, Redis, a worker and scheduler.

## Production configuration
Create a root-owned environment file (mode 0600). Required values include DATABASE_URL, PHANTOM_REDIS_URL, PHANTOM_AUTH_SECRET, PHANTOM_BOOTSTRAP_EMAIL, PHANTOM_BOOTSTRAP_PASSWORD, PHANTOM_ENV=production and PHANTOM_CORS_ORIGINS. Generate independent random credentials. Never expose backend secrets through VITE_* variables.

Run `alembic upgrade head` before starting a new application revision. Alembic is the only schema migration authority.

## Linux services
Install Python dependencies into a virtualenv and build the frontend with `npm ci && npm run build`. Run separate systemd units:
- API: `uvicorn app.main:app --host 127.0.0.1 --port 8080`
- worker: the repository worker entry point
- scheduler: the repository scheduler entry point
Use Restart=on-failure, a dedicated unprivileged user, EnvironmentFile, and journal logging.

Nginx serves `dist/`, proxies `/api/` and websocket traffic to 127.0.0.1:8080, redirects HTTP to HTTPS, and uses certificates managed by the site's PKI/ACME client.

## Windows
Use PostgreSQL and Redis-compatible services installed natively. Run API, worker and scheduler under a dedicated low-privilege service account using a service manager such as NSSM or Windows Service wrappers. Build the Vite frontend once and serve the static output behind IIS/Nginx. Store secrets in service environment configuration, not the repository.

## Backup and restore
Back up PostgreSQL with `pg_dump -Fc phantom > phantom-YYYYMMDD.dump`. Encrypt backups, store them off-host, define retention, and periodically test restores.
Restore into an empty database with `pg_restore --clean --if-exists --no-owner -d phantom phantom-YYYYMMDD.dump`, then run `alembic upgrade head`. Stop API/worker/scheduler during destructive restore and validate `/ready` before reopening traffic.

## Upgrade
1. Back up PostgreSQL.
2. Fetch the approved release.
3. Install pinned backend/frontend dependencies.
4. Build frontend.
5. Run `alembic upgrade head`.
6. Restart API, worker and scheduler.
7. Require `/ready` to report PostgreSQL and Redis healthy.
8. Smoke-test login, asset list, scan queue and report generation.

## Rollback
Application rollback is allowed only when its database schema remains compatible. If a release introduced an incompatible migration, restore the pre-upgrade database backup rather than improvising schema changes. Roll back the application revision, restart all services and verify readiness.

## Secret rotation
Rotate one dependency at a time. Update the authoritative secret store/service environment, restart affected processes, verify health, then revoke the previous credential. Rotate PHANTOM_AUTH_SECRET during a maintenance window because existing sessions become invalid. Database/Redis rotations must update API, worker and scheduler together.

## Retention
Configure PHANTOM_NET_WATCH_RETENTION_DAYS, PHANTOM_AUDIT_RETENTION_DAYS and PHANTOM_OPERATIONAL_RETENTION_DAYS. Production operators should schedule retention cleanup and backup verification as maintenance jobs. Security/audit retention must follow organizational policy and legal requirements.
