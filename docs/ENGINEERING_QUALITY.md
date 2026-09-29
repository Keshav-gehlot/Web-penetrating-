# PHANTOM engineering completion checklist

## API
All versioned JSON endpoints use the shared API envelope middleware, request IDs, structured generic errors and rate limiting. New list endpoints should accept limit/offset, documented sort keys and explicit filters. OpenAPI remains generated from FastAPI route/schema definitions; production can expose it only when PHANTOM documentation access policy permits.

## Database
Alembic is the schema authority. Migration 0019 adds finding/scan history storage and composite indexes for common workspace/time and finding queries. Foreign-key deletion behavior must be explicit: owned child records cascade; historical references that can survive deletion use SET NULL. Retention configuration covers audit, operational and Net-Watch events.

## Configuration
Production must supply auth/bootstrap/database/Redis credentials externally. Secrets are backend-only and never use VITE_ prefixes. Rotate credentials using docs/NATIVE_PRODUCTION.md.

## Test pyramid
Backend suites must cover unit, API, RBAC, PostgreSQL, scanners, Redis queue, worker lease/retry, scheduler dispatch, websocket authorization and reports. Frontend suites cover shared components, mocked APIs, navigation/RBAC and scan/finding/report workflows. E2E acceptance follows login -> asset -> scan -> queue -> worker -> live events -> findings -> investigation -> remediation -> rescan -> report.

## Release gate
A release is not production-ready until: migrations upgrade from the previous production head; backend tests pass; TypeScript passes; Vite production build passes; API /ready reports database and Redis healthy; worker heartbeat is current; scheduler heartbeat is current; and a smoke E2E flow passes.

## Product polish
Use the PHANTOM shared design system for all new UI. Global UX must include accessible keyboard focus, command/search affordances, API-disconnected/error states, responsive desktop/tablet layout and error boundaries. Saved filters, recent activity, notifications, profile and workspace switching should be persisted server-side rather than simulated in local UI.
