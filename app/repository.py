from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import desc, func, select
from sqlalchemy.orm import selectinload

from app.database import Database
from app.models import Alert, CommandEvent, HoneypotSession
from app.risk import RiskAnalyzer, RiskResult


class HoneypotRepository:
    def __init__(self, database: Database):
        self.database = database
        self.analyzer = RiskAnalyzer()

    def create_session(self, source_ip: str, source_port: int, username: str) -> str:
        session_id = str(uuid4())
        with self.database.session() as db:
            db.add(
                HoneypotSession(
                    id=session_id,
                    source_ip=source_ip,
                    source_port=source_port,
                    username=username or "unknown",
                )
            )
        return session_id

    def add_command(
        self,
        session_id: str,
        command: str,
        response: str,
        risk: RiskResult,
        used_llm: bool,
    ) -> None:
        with self.database.session() as db:
            session = db.get(HoneypotSession, session_id)
            if session is None:
                return
            session.command_count += 1
            session.risk_score = max(session.risk_score, risk.score)
            session.severity = self._higher_severity(session.severity, risk.severity)
            existing_mitre = [x for x in session.mitre_techniques.split(",") if x]
            session.mitre_techniques = ",".join(
                dict.fromkeys([*existing_mitre, *risk.mitre_techniques])
            )
            db.add(
                CommandEvent(
                    session_id=session_id,
                    command=command,
                    response=response,
                    risk_score=risk.score,
                    severity=risk.severity,
                    labels=",".join(risk.labels),
                    mitre_techniques=",".join(risk.mitre_techniques),
                    used_llm=used_llm,
                )
            )
            if risk.severity in {"HIGH", "CRITICAL"}:
                title = risk.labels[0] if risk.labels else "High-risk command detected"
                db.add(
                    Alert(
                        session_id=session_id,
                        severity=risk.severity,
                        title=title,
                        details=f"Command: {command}",
                    )
                )

    def close_session(self, session_id: str, summary: str = "") -> None:
        with self.database.session() as db:
            session = db.get(HoneypotSession, session_id)
            if session is None:
                return
            session.status = "CLOSED"
            session.ended_at = datetime.now(timezone.utc)
            session.classification = self.analyzer.classify_session(
                session.risk_score, session.command_count
            )
            session.summary = summary or self.heuristic_summary(
                session.classification,
                session.command_count,
                session.risk_score,
                session.mitre_techniques,
            )

    @staticmethod
    def heuristic_summary(
        classification: str, command_count: int, risk_score: int, mitre: str
    ) -> str:
        techniques = mitre.replace(",", ", ") or "không có"
        return (
            f"Phiên được phân loại {classification}, gồm {command_count} lệnh, "
            f"điểm rủi ro cao nhất {risk_score}/100. MITRE ATT&CK: {techniques}."
        )

    def get_session_commands(self, session_id: str) -> list[str]:
        with self.database.session() as db:
            rows = db.scalars(
                select(CommandEvent.command)
                .where(CommandEvent.session_id == session_id)
                .order_by(CommandEvent.id)
            ).all()
            return list(rows)

    def list_sessions(self, limit: int = 100) -> list[HoneypotSession]:
        with self.database.session() as db:
            return list(
                db.scalars(
                    select(HoneypotSession)
                    .order_by(desc(HoneypotSession.started_at))
                    .limit(min(max(limit, 1), 500))
                ).all()
            )

    def get_session(self, session_id: str) -> HoneypotSession | None:
        with self.database.session() as db:
            return db.scalar(
                select(HoneypotSession)
                .options(
                    selectinload(HoneypotSession.commands),
                    selectinload(HoneypotSession.alerts),
                )
                .where(HoneypotSession.id == session_id)
            )

    def list_alerts(self, limit: int = 100) -> list[Alert]:
        with self.database.session() as db:
            return list(
                db.scalars(select(Alert).order_by(desc(Alert.timestamp)).limit(limit)).all()
            )

    def acknowledge_alert(self, alert_id: int) -> bool:
        with self.database.session() as db:
            alert = db.get(Alert, alert_id)
            if alert is None:
                return False
            alert.acknowledged = True
            return True

    def stats(self) -> dict[str, int]:
        with self.database.session() as db:
            total_sessions = db.scalar(select(func.count(HoneypotSession.id))) or 0
            active_sessions = (
                db.scalar(
                    select(func.count(HoneypotSession.id)).where(
                        HoneypotSession.status == "ACTIVE"
                    )
                )
                or 0
            )
            dangerous_sessions = (
                db.scalar(
                    select(func.count(HoneypotSession.id)).where(
                        HoneypotSession.severity.in_(["HIGH", "CRITICAL"])
                    )
                )
                or 0
            )
            commands = db.scalar(select(func.count(CommandEvent.id))) or 0
            unacknowledged = (
                db.scalar(
                    select(func.count(Alert.id)).where(Alert.acknowledged.is_(False))
                )
                or 0
            )
            return {
                "total_sessions": int(total_sessions),
                "active_sessions": int(active_sessions),
                "dangerous_sessions": int(dangerous_sessions),
                "commands": int(commands),
                "unacknowledged_alerts": int(unacknowledged),
            }

    @staticmethod
    def _higher_severity(current: str, new: str) -> str:
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        return new if order.get(new, 0) > order.get(current, 0) else current
