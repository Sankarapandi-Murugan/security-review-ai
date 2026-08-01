from pathlib import Path

from fastapi.testclient import TestClient

from security_review.main import app

REAL_PUBLIC_REPO = "https://github.com/octocat/Hello-World"


def test_delete_assessment_returns_404_afterward() -> None:
    client = TestClient(app)
    create_response = client.post("/assessments", json={"name": "To delete", "description": ""})
    assert create_response.status_code == 201
    assessment_id = create_response.json()["id"]

    delete_response = client.delete(f"/assessments/{assessment_id}")
    assert delete_response.status_code == 204

    get_response = client.get(f"/assessments/{assessment_id}")
    assert get_response.status_code == 404


def test_delete_nonexistent_assessment_returns_404() -> None:
    client = TestClient(app)
    response = client.delete("/assessments/00000000-0000-0000-0000-000000000123")
    assert response.status_code == 404


def test_delete_repository_removes_clone_from_disk() -> None:
    client = TestClient(app)
    assessment_id = client.post(
        "/assessments", json={"name": "Repo delete review", "description": ""}
    ).json()["id"]

    ingest_response = client.post(
        f"/assessments/{assessment_id}/repositories",
        json={"name": "hello-world", "url": REAL_PUBLIC_REPO, "branch": "master"},
    )
    repository = ingest_response.json()

    ready = client.get(f"/assessments/{assessment_id}/repositories/{repository['id']}").json()
    assert ready["status"] == "ready"
    local_path = Path(ready["local_path"])
    assert local_path.is_dir()

    delete_response = client.delete(f"/assessments/{assessment_id}/repositories/{repository['id']}")
    assert delete_response.status_code == 204
    assert not local_path.exists()

    list_response = client.get(f"/assessments/{assessment_id}/repositories")
    assert list_response.json() == []

    get_response = client.get(f"/assessments/{assessment_id}/repositories/{repository['id']}")
    assert get_response.status_code == 404


def test_delete_nonexistent_repository_returns_404() -> None:
    client = TestClient(app)
    assessment_id = client.post(
        "/assessments", json={"name": "Repo delete 404 review", "description": ""}
    ).json()["id"]

    response = client.delete(f"/assessments/{assessment_id}/repositories/00000000-0000-0000-0000-000000000123")
    assert response.status_code == 404


def test_delete_assessment_cleans_up_cloned_repository() -> None:
    client = TestClient(app)
    assessment_id = client.post(
        "/assessments", json={"name": "Assessment cleanup review", "description": ""}
    ).json()["id"]

    ingest_response = client.post(
        f"/assessments/{assessment_id}/repositories",
        json={"name": "hello-world", "url": REAL_PUBLIC_REPO, "branch": "master"},
    )
    repository = ingest_response.json()
    ready = client.get(f"/assessments/{assessment_id}/repositories/{repository['id']}").json()
    local_path = Path(ready["local_path"])
    assert local_path.is_dir()

    delete_response = client.delete(f"/assessments/{assessment_id}")
    assert delete_response.status_code == 204
    assert not local_path.exists()
