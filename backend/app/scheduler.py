from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select

from .database import SessionLocal
from .models import Asset, Scan, Schedule, WorkspaceScope
from .queue import enqueue_scan
from .scanners.runner import PROFILES
from .security_scope import ScopeViolation, scope_snapshot, validate_target, validate_target_against_scope

log = logging.getLogger("phantom.scheduler")
INTERVAL = max(5, int(os.getenv("PHANTOM_SCHEDULER_INTERVAL", "15")))


async def dispatch_due() -> int:
    now = datetime.now(timezone.utc)
    dispatched = 0
    async with SessionLocal() as db:
        rows = await db.scalars(
            select(Schedule)
            .where(Schedule.enabled.is_(True), Schedule.next_run_at <= now)
            .order_by(Schedule.next_run_at)
            .with_for_update(skip_locked=True)
            .limit(20)
        )
        due = rows.all()
        for schedule in due:
            scope_row = await db.scalar(select(WorkspaceScope).where(WorkspaceScope.workspace_id == schedule.workspace_id))
            scope = scope_snapshot(scope_row)
            try:
                target = validate_target(schedule.target)
                validate_target_against_scope(target["target"], scope)
            except (ScopeViolation, ValueError, HTTPException) as exc:
                # Do not enqueue a scheduled scan outside the current workspace policy.
                # Advance the schedule so one invalid entry cannot hot-loop every cycle.
                schedule.last_run_at = now
                schedule.next_run_at = now + timedelta(seconds=schedule.interval_seconds)
                detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
                log.warning("Skipped scheduled scan id=%s workspace=%s: %s", schedule.id, schedule.workspace_id, detail)
                continue

            host = target["host"]
            asset = await db.scalar(select(Asset).where(Asset.workspace_id == schedule.workspace_id, Asset.host == host))
            if not asset:
                asset = Asset(id=str(uuid4()), host=host, target=target["target"], workspace_id=schedule.workspace_id)
                db.add(asset); await db.flush()
            scan = Scan(id=str(uuid4()), target=target["target"], host=host, profile=schedule.profile,
                        modules=list(PROFILES[schedule.profile]), status="queued", asset_id=asset.id,
                        workspace_id=schedule.workspace_id, attempt=1)
            db.add(scan)
            schedule.last_run_at = now
            schedule.next_run_at = now + timedelta(seconds=schedule.interval_seconds)
            await db.flush()
            await enqueue_scan(scan.id)
            dispatched += 1
        if due:
            await db.commit()
    return dispatched


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log.info("PHANTOM scheduler started interval=%ss", INTERVAL)
    while True:
        try:
            count = await dispatch_due()
            if count: log.info("Dispatched %s scheduled scan(s)", count)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Scheduled dispatch cycle failed")
        await asyncio.sleep(INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
