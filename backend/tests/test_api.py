import pytest
from fastapi.testclient import TestClient

from src.main import app
from src.config import settings


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def api_key():
    return settings.api_key


class TestHealthEndpoint:
    def test_health(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestAnalyzeEndpoint:
    def test_analyze_phishing(self, client, api_key):
        response = client.post(
            "/api/v1/analyze",
            json={
                "email_content": {
                    "from_address": "security@paypa1.com",
                    "from_name": "PayPal Security",
                    "subject": "URGENT: Account Suspended",
                    "body_text": "Click here immediately to verify your account.",
                    "body_html": '<a href="http://evil.com">http://paypal.com/verify</a>',
                }
            },
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["classification"] in ("Phishing", "Suspicious")
        assert "details" in data
        assert "heuristics" in data["details"]

    def test_analyze_safe(self, client, api_key):
        response = client.post(
            "/api/v1/analyze",
            json={
                "email_content": {
                    "from_address": "friend@company.com",
                    "from_name": "John",
                    "subject": "Lunch tomorrow?",
                    "body_text": "Want to grab lunch tomorrow at noon?",
                    "body_html": "",
                }
            },
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["classification"] == "Safe"

    def test_missing_api_key(self, client):
        response = client.post(
            "/api/v1/analyze",
            json={
                "email_content": {
                    "from_address": "test@test.com",
                    "subject": "Test",
                    "body_text": "Test",
                    "body_html": "",
                }
            },
        )
        assert response.status_code == 401

    def test_invalid_api_key(self, client):
        response = client.post(
            "/api/v1/analyze",
            json={
                "email_content": {
                    "from_address": "test@test.com",
                    "subject": "Test",
                    "body_text": "Test",
                    "body_html": "",
                }
            },
            headers={"X-API-Key": "wrong-key"},
        )
        assert response.status_code == 401
