from fastapi.testclient import TestClient

from security_review.main import app
from tests._auth_helpers import signup_headers


def test_create_and_list_assessments() -> None:
    client = TestClient(app)
    headers = signup_headers(client)

    create_response = client.post(
        "/assessments",
        json={"name": "Quarterly review", "description": "Automated security assessment"},
        headers=headers,
    )
    assert create_response.status_code == 201
    created = create_response.json()
    assert created["name"] == "Quarterly review"
    assert created["status"] == "created"
    assert created["description"] == "Automated security assessment"

    list_response = client.get("/assessments", headers=headers)
    assert list_response.status_code == 200
    items = list_response.json()
    assert any(item["id"] == created["id"] for item in items)
