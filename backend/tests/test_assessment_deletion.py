from pathlib import Path

from fastapi.testclient import TestClient

from security_review.main import app
from tests._auth_helpers import signup_headers

REAL_PUBLIC_REPO = "https://github.com/octocat/Hello-World"


def test_delete_assessment_returns_404_afterward() -> None:
    client = TestClient(app)
    headers = signup_headers(client)
    create_response = client.post(
        "/assessments", json={"name": "To delete", "description": ""}, headers=headers
    )
    assert create_response.status_code == 201
    assessment_id = create_response.json()["id"]

    delete_response = client.delete(f"/assessments/{assessment_id}", headers=headers)
    assert delete_response.status_code == 204

    get_response = client.get(f"/assessments/{assessment_id}", headers=headers)
    assert get_response.status_code == 404


def test_delete_nonexistent_assessment_returns_404() -> None:
    client = TestClient(app)
    headers = signup_headers(client)
    response = client.delete("/assessments/00000000-0000-0000-0000-000000000123", headers=headers)
    assert response.status_code == 404


def test_delete_repository_removes_clone_from_disk() -> None:
    client = TestClient(app)
    headers = signup_headers(client)
    assessment_id = client.post(
        "/assessments", json={"name": "Repo delete review", "description": ""}, headers=headers
    ).json()["id"]

    ingest_response = client.post(
        f"/assessments/{assessment_id}/repositories",
        json={"name": "hello-world", "url": REAL_PUBLIC_REPO, "branch": "master"},
        headers=headers,
    )
    repository = ingest_response.json()

    ready = client.get(
        f"/assessments/{assessment_id}/repositories/{repository['id']}", headers=headers
    ).json()
    assert ready["status"] == "ready"
    local_path = Path(ready["local_path"])
    assert local_path.is_dir()

    delete_response = client.delete(
        f"/assessments/{assessment_id}/repositories/{repository['id']}", headers=headers
    )
    assert delete_response.status_code == 204
    assert not local_path.exists()

    list_response = client.get(f"/assessments/{assessment_id}/repositories", headers=headers)
    assert list_response.json() == []

    get_response = client.get(
        f"/assessments/{assessment_id}/repositories/{repository['id']}", headers=headers
    )
    assert get_response.status_code == 404


def test_delete_nonexistent_repository_returns_404() -> None:
    client = TestClient(app)
    headers = signup_headers(client)
    assessment_id = client.post(
        "/assessments", json={"name": "Repo delete 404 review", "description": ""}, headers=headers
    ).json()["id"]

    response = client.delete(
        f"/assessments/{assessment_id}/repositories/00000000-0000-0000-0000-000000000123",
        headers=headers,
    )
    assert response.status_code == 404


def test_delete_assessment_cleans_up_cloned_repository() -> None:
    client = TestClient(app)
    headers = signup_headers(client)
    assessment_id = client.post(
        "/assessments", json={"name": "Assessment cleanup review", "description": ""}, headers=headers
    ).json()["id"]

    ingest_response = client.post(
        f"/assessments/{assessment_id}/repositories",
        json={"name": "hello-world", "url": REAL_PUBLIC_REPO, "branch": "master"},
        headers=headers,
    )
    repository = ingest_response.json()
    ready = client.get(
        f"/assessments/{assessment_id}/repositories/{repository['id']}", headers=headers
    ).json()
    local_path = Path(ready["local_path"])
    assert local_path.is_dir()

    delete_response = client.delete(f"/assessments/{assessment_id}", headers=headers)
    assert delete_response.status_code == 204
    assert not local_path.exists()
