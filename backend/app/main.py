from __future__ import annotations

from contextlib import asynccontextmanager
import socket

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .auth import Principal
from .config import settings
from .database import init_db
from .rbac import require_permission
from .security_scope import resolve_public_host, validate_target


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version="2.0.0",
    description="PHANTOM Security Operations API for authorized, bounded security assessments.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


class TargetRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "phantom-api", "version": "2.0.0"}


@app.post("/api/v1/targets/validate")
async def target_validate(request: TargetRequest) -> dict[str, object]:
    return validate_target(request.target)


@app.get("/api/v1/assets/{host}/resolve")
async def resolve_host(
    host: str,
    principal: Principal = Depends(require_permission("scan:view")),
) -> dict[str, object]:
    del principal
    addresses = resolve_public_host(host)
    return {"host": host.rstrip(".").lower(), "addresses": addresses}


from .api.assets import router as assets_router
from .api.auth import router as auth_router
from .api.audit import router as audit_router
from .api.dashboard import router as dashboard_router
from .api.events import router as events_router
from .api.findings import router as findings_router
from .api.health import router as health_router
from .api.investigations import router as investigations_router
from .api.reports import router as reports_router
from .api.scans import router as scans_router
from .api.system import router as system_router
from .api.workspaces import router as workspaces_router


for router in (
    auth_router,
    assets_router,
    scans_router,
    reports_router,
    events_router,
    findings_router,
    investigations_router,
    audit_router,
    workspaces_router,
    dashboard_router,
    health_router,
    system_router,
):
    app.include_router(router)
