from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class HoneypotSession(Base):
    __tablename__ = "honeypot_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    source_port: Mapped[int] = mapped_column(Integer, default=0)
    username: Mapped[str] = mapped_column(String(128), default="unknown")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="LOW", index=True)
    classification: Mapped[str] = mapped_column(String(32), default="UNCLASSIFIED")
    command_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(Text, default="")
    mitre_techniques: Mapped[str] = mapped_column(Text, default="")

    commands: Mapped[List[CommandEvent]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    alerts: Mapped[List[Alert]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class CommandEvent(Base):
    __tablename__ = "command_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("honeypot_sessions.id", ondelete="CASCADE"), index=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    command: Mapped[str] = mapped_column(Text)
    response: Mapped[str] = mapped_column(Text, default="")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(16), default="LOW")
    labels: Mapped[str] = mapped_column(Text, default="")
    mitre_techniques: Mapped[str] = mapped_column(Text, default="")
    used_llm: Mapped[bool] = mapped_column(Boolean, default=False)

    session: Mapped[HoneypotSession] = relationship(back_populates="commands")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(
        ForeignKey("honeypot_sessions.id", ondelete="CASCADE"), index=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(255))
    details: Mapped[str] = mapped_column(Text, default="")
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    session: Mapped[HoneypotSession] = relationship(back_populates="alerts")
