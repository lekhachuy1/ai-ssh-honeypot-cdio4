from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import Settings, get_settings
from app.database import Database
from app.llm import OllamaClient
from app.repository import HoneypotRepository
from app.ssh_server import start_ssh_server

security = HTTPBasic()
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or get_settings()
    database = Database(config.database_url)
    database.create_all()
    repository = HoneypotRepository(database)
    llm = OllamaClient(config)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = config
        app.state.database = database
        app.state.repository = repository
        app.state.llm = llm
        app.state.ssh_listener = None
        if config.start_ssh_server:
            app.state.ssh_listener = await start_ssh_server(config, repository, llm)
        yield
        listener = app.state.ssh_listener
        if listener is not None:
            listener.close()
            await listener.wait_closed()

    app = FastAPI(title=config.app_name, version="0.1.0", lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    def require_admin(credentials: HTTPBasicCredentials = Depends(security)) -> str:
        username_ok = secrets.compare_digest(credentials.username, config.admin_username)
        password_ok = secrets.compare_digest(credentials.password, config.admin_password)
        if not (username_ok and password_ok):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid administrator credentials",
                headers={"WWW-Authenticate": "Basic"},
            )
        return credentials.username

    @app.get("/api/health")
    def health() -> dict:
        return {
            "status": "ok",
            "app": config.app_name,
            "ssh_enabled": config.start_ssh_server,
            "llm_enabled": config.enable_llm,
        }

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, _admin: str = Depends(require_admin)):
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "stats": repository.stats(),
                "sessions": repository.list_sessions(limit=10),
                "alerts": repository.list_alerts(limit=8),
                "settings": config,
            },
        )

    @app.get("/sessions", response_class=HTMLResponse)
    def sessions_page(request: Request, _admin: str = Depends(require_admin)):
        return templates.TemplateResponse(
            request=request,
            name="sessions.html",
            context={"sessions": repository.list_sessions(limit=200), "settings": config},
        )

    @app.get("/sessions/{session_id}", response_class=HTMLResponse)
    def session_detail(
        request: Request,
        session_id: str,
        _admin: str = Depends(require_admin),
    ):
        item = repository.get_session(session_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Session not found")
        item.commands.sort(key=lambda event: event.id)
        item.alerts.sort(key=lambda alert: alert.id)
        return templates.TemplateResponse(
            request=request,
            name="session_detail.html",
            context={"item": item, "settings": config},
        )

    @app.get("/alerts", response_class=HTMLResponse)
    def alerts_page(request: Request, _admin: str = Depends(require_admin)):
        return templates.TemplateResponse(
            request=request,
            name="alerts.html",
            context={"alerts": repository.list_alerts(limit=300), "settings": config},
        )

    @app.post("/alerts/{alert_id}/acknowledge")
    def acknowledge_alert_page(
        alert_id: int, _admin: str = Depends(require_admin)
    ) -> RedirectResponse:
        if not repository.acknowledge_alert(alert_id):
            raise HTTPException(status_code=404, detail="Alert not found")
        return RedirectResponse(url="/alerts", status_code=303)

    @app.get("/api/stats")
    def api_stats(_admin: str = Depends(require_admin)) -> dict:
        return repository.stats()

    @app.get("/api/sessions")
    def api_sessions(limit: int = 100, _admin: str = Depends(require_admin)) -> list[dict]:
        return [serialize_session(item) for item in repository.list_sessions(limit=limit)]

    @app.get("/api/sessions/{session_id}")
    def api_session(
        session_id: str, _admin: str = Depends(require_admin)
    ) -> JSONResponse:
        item = repository.get_session(session_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Session not found")
        payload = serialize_session(item)
        payload["commands"] = [
            {
                "id": event.id,
                "timestamp": event.timestamp.isoformat(),
                "command": event.command,
                "response": event.response,
                "risk_score": event.risk_score,
                "severity": event.severity,
                "labels": [x for x in event.labels.split(",") if x],
                "mitre_techniques": [x for x in event.mitre_techniques.split(",") if x],
                "used_llm": event.used_llm,
            }
            for event in sorted(item.commands, key=lambda row: row.id)
        ]
        return JSONResponse(payload)

    @app.post("/api/alerts/{alert_id}/acknowledge")
    def api_acknowledge_alert(
        alert_id: int, _admin: str = Depends(require_admin)
    ) -> dict:
        if not repository.acknowledge_alert(alert_id):
            raise HTTPException(status_code=404, detail="Alert not found")
        return {"status": "acknowledged", "alert_id": alert_id}

    return app


def serialize_session(item) -> dict:  # ORM serializer kept explicit for a small project
    return {
        "id": item.id,
        "source_ip": item.source_ip,
        "source_port": item.source_port,
        "username": item.username,
        "started_at": item.started_at.isoformat(),
        "ended_at": item.ended_at.isoformat() if item.ended_at else None,
        "status": item.status,
        "risk_score": item.risk_score,
        "severity": item.severity,
        "classification": item.classification,
        "command_count": item.command_count,
        "summary": item.summary,
        "mitre_techniques": [x for x in item.mitre_techniques.split(",") if x],
    }
