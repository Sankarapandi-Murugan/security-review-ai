import uuid

from fastapi.testclient import TestClient

from security_review.main import app


def _signup(client: TestClient) -> str:
    email = f"user-{uuid.uuid4().hex}@example.com"
    response = client.post(
        "/auth/signup",
        json={"organization_name": "Pagination org", "email": email, "password": "supersecret123"},
    )
    assert response.status_code == 201
    return response.json()["access_token"]


def test_list_assessments_pagination() -> None:
    client = TestClient(app)
    token = _signup(client)
    headers = {"Authorization": f"Bearer {token}"}

    # The Free plan caps assessments at 3; upgrade to Pro so this test can create 5.
    upgrade = client.post("/billing/subscribe", json={"plan": "pro"}, headers=headers)
    assert upgrade.status_code == 200

    created_ids = []
    for i in range(5):
        response = client.post(
            "/assessments",
            json={"name": f"Assessment {i}", "description": ""},
            headers=headers,
        )
        assert response.status_code == 201
        created_ids.append(response.json()["id"])

    first_page = client.get("/assessments?limit=2&offset=0", headers=headers)
    assert first_page.status_code == 200
    assert len(first_page.json()) == 2
    assert first_page.headers["X-Total-Count"] == "5"
    # Newest-first ordering: the most recently created assessment appears first.
    assert first_page.json()[0]["id"] == created_ids[-1]

    second_page = client.get("/assessments?limit=2&offset=2", headers=headers)
    assert second_page.status_code == 200
    assert len(second_page.json()) == 2

    third_page = client.get("/assessments?limit=2&offset=4", headers=headers)
    assert third_page.status_code == 200
    assert len(third_page.json()) == 1

    all_ids_across_pages = {item["id"] for item in first_page.json() + second_page.json() + third_page.json()}
    assert all_ids_across_pages == set(created_ids)


def test_list_assessments_default_limit_applies() -> None:
    client = TestClient(app)
    token = _signup(client)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/assessments", headers=headers)
    assert response.status_code == 200
    assert response.headers["X-Total-Count"] == "0"
    assert response.json() == []


def test_list_assessments_rejects_invalid_limit() -> None:
    client = TestClient(app)
    token = _signup(client)
    headers = {"Authorization": f"Bearer {token}"}

    too_small = client.get("/assessments?limit=0", headers=headers)
    assert too_small.status_code == 422

    too_large = client.get("/assessments?limit=500", headers=headers)
    assert too_large.status_code == 422

    negative_offset = client.get("/assessments?offset=-1", headers=headers)
    assert negative_offset.status_code == 422
