from __future__ import annotations
from datetime import datetime
from typing import Any
from uuid import uuid4
from sqlalchemy import DateTime,ForeignKey,JSON,String,func
from sqlalchemy.orm import Mapped,mapped_column
from .database import Base

class FindingHistory(Base):
 __tablename__="finding_history"
 id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid4()))
 finding_id:Mapped[str]=mapped_column(ForeignKey("findings.id",ondelete="CASCADE"),index=True)
 workspace_id:Mapped[str]=mapped_column(ForeignKey("workspaces.id",ondelete="CASCADE"),index=True)
 event_type:Mapped[str]=mapped_column(String(64),index=True)
 snapshot:Mapped[dict[str,Any]]=mapped_column(JSON,default=dict)
 actor_id:Mapped[str|None]=mapped_column(ForeignKey("users.id",ondelete="SET NULL"),nullable=True)
 created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),server_default=func.now(),index=True)

class ScanHistory(Base):
 __tablename__="scan_history"
 id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid4()))
 scan_id:Mapped[str]=mapped_column(ForeignKey("scans.id",ondelete="CASCADE"),index=True)
 workspace_id:Mapped[str]=mapped_column(ForeignKey("workspaces.id",ondelete="CASCADE"),index=True)
 event_type:Mapped[str]=mapped_column(String(64),index=True)
 snapshot:Mapped[dict[str,Any]]=mapped_column(JSON,default=dict)
 created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),server_default=func.now(),index=True)
