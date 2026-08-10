from fastapi.testclient import TestClient

from app.config import Settings
from app.web import create_app


def test_health_endpoint_without_ssh_server():
    settings = Settings(
        start_ssh_server=False,
        database_url="sqlite+pysqlite:///:memory:",
        admin_username="admin",
        admin_password="test-password",
    )
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


def test_stats_requires_authentication():
    settings = Settings(
        start_ssh_server=False,
        database_url="sqlite+pysqlite:///:memory:",
        admin_username="admin",
        admin_password="test-password",
    )
    app = create_app(settings)
    with TestClient(app) as client:
        assert client.get("/api/stats").status_code == 401
        response = client.get("/api/stats", auth=("admin", "test-password"))
        assert response.status_code == 200
