import uuid

from fastapi.testclient import TestClient

from security_review.main import app
from tests._auth_helpers import signup_headers


def _capture_invite_url(monkeypatch) -> dict:
    captured = {}
    from security_review.infrastructure.email import email_provider as email_provider_module

    def _capture(self, to_email, organization_name, set_password_url):
        captured["set_password_url"] = set_password_url

    monkeypatch.setattr(email_provider_module.ConsoleEmailProvider, "send_invite_email", _capture)
    return captured


def _invite_and_activate(client: TestClient, owner_headers: dict, monkeypatch, email: str, role: str) -> dict:
    """Invite a teammate as the owner, capture the invite link, set their password,
    and log in as them -- returns their auth headers."""
    captured = _capture_invite_url(monkeypatch)

    invite_response = client.post(
        "/team/invite", json={"email": email, "role": role}, headers=owner_headers
    )
    assert invite_response.status_code == 201, invite_response.text
    assert "set_password_url" in captured

    reset_token = captured["set_password_url"].split("reset_token=")[1]
    reset_response = client.post(
        "/auth/reset-password", json={"token": reset_token, "new_password": "teammate-password-1"}
    )
    assert reset_response.status_code == 200

    login_response = client.post("/auth/login", json={"email": email, "password": "teammate-password-1"})
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_owner_can_invite_and_list_members(monkeypatch):
    client = TestClient(app)
    owner_headers = signup_headers(client)

    member_email = f"member-{uuid.uuid4().hex}@example.com"
    _invite_and_activate(client, owner_headers, monkeypatch, member_email, "member")

    members_response = client.get("/team/members", headers=owner_headers)
    assert members_response.status_code == 200
    emails = {member["email"] for member in members_response.json()}
    assert member_email in emails


def test_invite_rejects_duplicate_email(monkeypatch):
    client = TestClient(app)
    owner_headers = signup_headers(client)
    _capture_invite_url(monkeypatch)

    email = f"dup-{uuid.uuid4().hex}@example.com"
    first = client.post("/team/invite", json={"email": email, "role": "member"}, headers=owner_headers)
    assert first.status_code == 201

    second = client.post("/team/invite", json={"email": email, "role": "member"}, headers=owner_headers)
    assert second.status_code == 409


def test_member_cannot_invite_teammates(monkeypatch):
    client = TestClient(app)
    owner_headers = signup_headers(client)
    member_email = f"member-{uuid.uuid4().hex}@example.com"
    member_headers = _invite_and_activate(client, owner_headers, monkeypatch, member_email, "member")

    response = client.post(
        "/team/invite",
        json={"email": f"another-{uuid.uuid4().hex}@example.com", "role": "member"},
        headers=member_headers,
    )
    assert response.status_code == 403


def test_admin_can_invite_but_not_change_roles(monkeypatch):
    client = TestClient(app)
    owner_headers = signup_headers(client)
    admin_email = f"admin-{uuid.uuid4().hex}@example.com"
    admin_headers = _invite_and_activate(client, owner_headers, monkeypatch, admin_email, "admin")

    invite_response = client.post(
        "/team/invite",
        json={"email": f"invited-by-admin-{uuid.uuid4().hex}@example.com", "role": "member"},
        headers=admin_headers,
    )
    assert invite_response.status_code == 201

    members = client.get("/team/members", headers=owner_headers).json()
    admin_user_id = next(m["id"] for m in members if m["email"] == admin_email)

    role_change_response = client.patch(
        f"/team/members/{admin_user_id}/role", json={"role": "owner"}, headers=admin_headers
    )
    assert role_change_response.status_code == 403


def test_only_owner_can_change_roles_and_remove_members(monkeypatch):
    client = TestClient(app)
    owner_headers = signup_headers(client)
    member_email = f"member-{uuid.uuid4().hex}@example.com"
    _invite_and_activate(client, owner_headers, monkeypatch, member_email, "member")

    members = client.get("/team/members", headers=owner_headers).json()
    member_user_id = next(m["id"] for m in members if m["email"] == member_email)

    promote_response = client.patch(
        f"/team/members/{member_user_id}/role", json={"role": "admin"}, headers=owner_headers
    )
    assert promote_response.status_code == 200
    assert promote_response.json()["role"] == "admin"

    remove_response = client.delete(f"/team/members/{member_user_id}", headers=owner_headers)
    assert remove_response.status_code == 204

    members_after = client.get("/team/members", headers=owner_headers).json()
    assert all(m["id"] != member_user_id for m in members_after)


def test_cannot_demote_or_remove_the_last_owner():
    client = TestClient(app)
    owner_headers = signup_headers(client)

    members = client.get("/team/members", headers=owner_headers).json()
    owner_user_id = members[0]["id"]

    demote_response = client.patch(
        f"/team/members/{owner_user_id}/role", json={"role": "member"}, headers=owner_headers
    )
    assert demote_response.status_code == 409

    remove_response = client.delete(f"/team/members/{owner_user_id}", headers=owner_headers)
    assert remove_response.status_code == 409


def test_role_change_and_remove_return_404_for_unknown_member():
    client = TestClient(app)
    owner_headers = signup_headers(client)
    fake_id = str(uuid.uuid4())

    role_response = client.patch(
        f"/team/members/{fake_id}/role", json={"role": "member"}, headers=owner_headers
    )
    assert role_response.status_code == 404

    remove_response = client.delete(f"/team/members/{fake_id}", headers=owner_headers)
    assert remove_response.status_code == 404


# ---------------------------------------------------------------------------
# RBAC enforcement on existing endpoints
# ---------------------------------------------------------------------------


def test_billing_subscribe_requires_owner_role(monkeypatch):
    client = TestClient(app)
    owner_headers = signup_headers(client)
    member_email = f"member-{uuid.uuid4().hex}@example.com"
    member_headers = _invite_and_activate(client, owner_headers, monkeypatch, member_email, "member")

    response = client.post("/billing/subscribe", json={"plan": "pro"}, headers=member_headers)
    assert response.status_code == 403

    owner_response = client.post("/billing/subscribe", json={"plan": "pro"}, headers=owner_headers)
    assert owner_response.status_code == 200


def test_delete_assessment_requires_owner_or_admin_role(monkeypatch):
    client = TestClient(app)
    owner_headers = signup_headers(client)
    member_email = f"member-{uuid.uuid4().hex}@example.com"
    member_headers = _invite_and_activate(client, owner_headers, monkeypatch, member_email, "member")

    assessment = client.post(
        "/assessments", json={"name": "RBAC delete test"}, headers=owner_headers
    ).json()

    delete_as_member = client.delete(f"/assessments/{assessment['id']}", headers=member_headers)
    assert delete_as_member.status_code == 403

    delete_as_owner = client.delete(f"/assessments/{assessment['id']}", headers=owner_headers)
    assert delete_as_owner.status_code == 204


def test_member_can_still_create_assessments_and_scan_jobs(monkeypatch):
    client = TestClient(app)
    owner_headers = signup_headers(client)
    member_email = f"member-{uuid.uuid4().hex}@example.com"
    member_headers = _invite_and_activate(client, owner_headers, monkeypatch, member_email, "member")

    assessment_response = client.post(
        "/assessments", json={"name": "Member-created assessment"}, headers=member_headers
    )
    assert assessment_response.status_code == 201

    scan_response = client.post(
        f"/assessments/{assessment_response.json()['id']}/scan-jobs",
        json={"agent_type": "white_box", "target": "requirements.txt"},
        headers=member_headers,
    )
    assert scan_response.status_code == 201
