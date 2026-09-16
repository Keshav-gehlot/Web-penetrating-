from contextlib import asynccontextmanager
import ipaddress
import socket
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .database import init_db

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(title="PHANTOM Security API", version="2.0.0", lifespan=lifespan)

class TargetRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)

def normalize_target(value: str) -> str:
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be a valid HTTP(S) hostname or URL")
    return value.rstrip("/")

def validate_target(value: str) -> dict:
    try:
        normalized = normalize_target(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    host = urlparse(normalized).hostname
    try:
        ip = ipaddress.ip_address(host)
        is_ip = True
        blocked = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    except ValueError:
        is_ip = False
        blocked = host in {"localhost", "localhost.localdomain"} or host.endswith(".local")
    if blocked:
        raise HTTPException(status_code=400, detail="Private, loopback, link-local, multicast, reserved, or local targets are not allowed")
    return {"target": normalized, "host": host, "is_ip": is_ip}

@app.get("/health")
async def health():
    return {"status": "ok", "service": "phantom-api", "version": "2.0.0"}

@app.post("/api/v1/targets/validate")
async def target_validate(request: TargetRequest):
    return validate_target(request.target)

@app.get("/api/v1/assets/{host}/resolve")
async def resolve_host(host: str):
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
    except socket.gaierror as exc:
        raise HTTPException(status_code=404, detail=f"DNS resolution failed: {exc}")
    return {"host": host, "addresses": addresses}

from .api.scans import router as scans_router
from .api.reports import router as reports_router
from .api.events import router as events_router
from .api.findings import router as findings_router
from .api.investigations import router as investigations_router

app.include_router(scans_router)
app.include_router(reports_router)
app.include_router(events_router)
app.include_router(findings_router)
app.include_router(investigations_router)
