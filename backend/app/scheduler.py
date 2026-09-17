from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import select

from .database import SessionLocal
from .models import Asset, Scan, Schedule
from .queue import enqueue_scan
from .scanners.runner import PROFILES

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
            target = schedule.target
            host = target.split("://", 1)[-1].split("/", 1)[0].lower().rstrip(".")
            asset = await db.scalar(select(Asset).where(Asset.workspace_id == schedule.workspace_id, Asset.host == host))
            if not asset:
                asset = Asset(id=str(uuid4()), host=host, target=target, workspace_id=schedule.workspace_id)
                db.add(asset); await db.flush()
            scan = Scan(id=str(uuid4()), target=target, host=host, profile=schedule.profile,
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
