from pathlib import Path

from fastapi.testclient import TestClient

from security_review.main import app

REAL_PUBLIC_REPO = "https://github.com/octocat/Hello-World"


def test_repository_ingestion_and_scan_flow() -> None:
    client = TestClient(app)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Repo review", "description": "Analyze a repository"},
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    ingest_response = client.post(
        f"/assessments/{assessment_id}/repositories",
        json={"name": "hello-world", "url": REAL_PUBLIC_REPO, "branch": "master"},
    )
    assert ingest_response.status_code == 201
    repository = ingest_response.json()
    assert repository["name"] == "hello-world"
    assert repository["branch"] == "master"
    # Cloning runs as a background task, so the creation response always reflects
    # the initial state before ingestion has finished.
    assert repository["status"] == "pending"
    assert repository["local_path"] is None

    # By the time TestClient's request/response cycle completes, the background
    # clone has already run (Starlette executes background tasks before returning).
    get_response = client.get(f"/assessments/{assessment_id}/repositories/{repository['id']}")
    assert get_response.status_code == 200
    ready_repository = get_response.json()
    assert ready_repository["status"] == "ready"
    assert ready_repository["local_path"] is not None
    assert Path(ready_repository["local_path"]).is_dir()
    assert ready_repository["commit_hash"]

    scan_response = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "dependency_security", "repository_id": repository["id"]},
    )
    assert scan_response.status_code == 201
    scan_job = scan_response.json()
    assert scan_job["status"] == "pending"
    assert scan_job["target"] == ready_repository["local_path"]


def test_repository_ingestion_rejects_disallowed_url_scheme() -> None:
    client = TestClient(app)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Invalid scheme review", "description": "Test URL validation"},
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    ingest_response = client.post(
        f"/assessments/{assessment_id}/repositories",
        json={"name": "local-file", "url": "file:///etc/passwd", "branch": "main"},
    )
    assert ingest_response.status_code == 201
    repository = ingest_response.json()

    get_response = client.get(f"/assessments/{assessment_id}/repositories/{repository['id']}")
    assert get_response.status_code == 200
    failed_repository = get_response.json()
    assert failed_repository["status"] == "failed"
    assert failed_repository["local_path"] is None
    assert "http" in failed_repository["error_message"]


def test_scan_job_rejects_repository_that_failed_to_ingest() -> None:
    client = TestClient(app)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Failed ingest review", "description": "Test not-ready repository"},
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    ingest_response = client.post(
        f"/assessments/{assessment_id}/repositories",
        json={"name": "bad-repo", "url": "https://github.com/example/does-not-exist-repo", "branch": "main"},
    )
    assert ingest_response.status_code == 201
    repository = ingest_response.json()

    scan_response = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "white_box", "repository_id": repository["id"]},
    )
    assert scan_response.status_code == 409


def test_list_and_get_assessment_repositories() -> None:
    client = TestClient(app)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Repository catalog review", "description": "Test repository listing"},
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    ingest_response = client.post(
        f"/assessments/{assessment_id}/repositories",
        json={"name": "hello-world", "url": REAL_PUBLIC_REPO, "branch": "master"},
    )
    assert ingest_response.status_code == 201
    repository = ingest_response.json()

    list_response = client.get(f"/assessments/{assessment_id}/repositories")
    assert list_response.status_code == 200
    repositories = list_response.json()
    assert len(repositories) == 1
    assert repositories[0]["id"] == repository["id"]
    assert repositories[0]["name"] == "hello-world"

    get_response = client.get(f"/assessments/{assessment_id}/repositories/{repository['id']}")
    assert get_response.status_code == 200
    repository_detail = get_response.json()
    assert repository_detail["id"] == repository["id"]
    assert repository_detail["url"] == REAL_PUBLIC_REPO
    assert repository_detail["status"] == "ready"

