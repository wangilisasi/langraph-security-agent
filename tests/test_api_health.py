from fastapi.testclient import TestClient

from app.api.server import app


def test_health_returns_ok_and_version():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == app.version

