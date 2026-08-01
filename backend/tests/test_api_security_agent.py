import json

from security_review.infrastructure.scanners.api_security_agent import ApiSecurityAgent


class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class _FakeClient:
    """Duck-typed stand-in for httpx.Client keyed by exact URL."""

    def __init__(self, responses: dict[str, _FakeResponse]) -> None:
        self._responses = responses

    def get(self, url: str, headers: dict[str, str] | None = None) -> _FakeResponse:
        if url not in self._responses:
            return _FakeResponse(status_code=404)
        return self._responses[url]


def test_extract_documented_paths_normalizes_trailing_slash():
    spec = {"paths": {"/users/": {}, "/users/{id}": {}}}
    paths = ApiSecurityAgent._extract_documented_paths(spec)
    assert paths == {"/users", "/users/{id}"}


def test_fetch_openapi_spec_finds_first_valid_json_spec():
    agent = ApiSecurityAgent()
    spec_body = json.dumps({"paths": {"/users": {}}})
    client = _FakeClient({"https://api.example.com/openapi.json": _FakeResponse(text=spec_body)})

    spec, spec_path = agent._fetch_openapi_spec(client, "https://api.example.com")

    assert spec_path == "/openapi.json"
    assert spec == {"paths": {"/users": {}}}


def test_fetch_openapi_spec_returns_none_when_nothing_found():
    agent = ApiSecurityAgent()
    client = _FakeClient({})

    spec, spec_path = agent._fetch_openapi_spec(client, "https://api.example.com")

    assert spec is None
    assert spec_path is None


def test_probe_hidden_endpoints_flags_undocumented_live_endpoint():
    agent = ApiSecurityAgent()
    client = _FakeClient({"https://api.example.com/admin": _FakeResponse(status_code=200)})

    findings = agent._probe_hidden_endpoints(client, "https://api.example.com", documented_paths=set())

    matching = [f for f in findings if "/admin" in f.title]
    assert matching
    assert matching[0].severity.value == "high"


def test_probe_hidden_endpoints_skips_documented_paths():
    agent = ApiSecurityAgent()
    client = _FakeClient({"https://api.example.com/admin": _FakeResponse(status_code=200)})

    findings = agent._probe_hidden_endpoints(
        client, "https://api.example.com", documented_paths={"/admin"}
    )

    assert not any("/admin" in f.title for f in findings)


def test_probe_hidden_endpoints_treats_401_as_access_controlled():
    agent = ApiSecurityAgent()
    client = _FakeClient({"https://api.example.com/actuator/env": _FakeResponse(status_code=401)})

    findings = agent._probe_hidden_endpoints(client, "https://api.example.com", documented_paths=set())

    matching = [f for f in findings if "actuator/env" in f.title]
    assert matching
    assert matching[0].severity.value == "medium"
    assert "access-controlled" in matching[0].description


def test_execute_url_target_without_authorization_skips_discovery():
    findings = ApiSecurityAgent().execute("https://127.0.0.1:1/api", authorized=False)
    assert any("authorization" in finding.title.lower() for finding in findings)


def test_execute_none_target_returns_empty():
    assert ApiSecurityAgent().execute(None) == []


def test_check_rate_limiting_flags_missing_429():
    agent = ApiSecurityAgent()

    class _AlwaysOkClient:
        def __init__(self) -> None:
            self.calls = 0

        def get(self, url: str, headers: dict[str, str] | None = None) -> _FakeResponse:
            self.calls += 1
            return _FakeResponse(status_code=200)

    client = _AlwaysOkClient()
    findings = agent._check_rate_limiting(client, "https://api.example.com/data")

    assert any("no rate limiting" in finding.title.lower() for finding in findings)
    assert client.calls > 1


def test_check_rate_limiting_stops_and_passes_on_429():
    agent = ApiSecurityAgent()

    class _EnforcingClient:
        def __init__(self) -> None:
            self.calls = 0

        def get(self, url: str, headers: dict[str, str] | None = None) -> _FakeResponse:
            self.calls += 1
            if self.calls >= 3:
                return _FakeResponse(status_code=429)
            return _FakeResponse(status_code=200)

    client = _EnforcingClient()
    findings = agent._check_rate_limiting(client, "https://api.example.com/data")

    assert findings == []
    assert client.calls == 3


def test_check_jwt_handling_flags_alg_none_acceptance():
    agent = ApiSecurityAgent()

    class _VulnerableClient:
        def get(self, url: str, headers: dict[str, str] | None = None) -> _FakeResponse:
            if headers and "Authorization" in headers:
                return _FakeResponse(status_code=200)
            return _FakeResponse(status_code=401)

    findings = agent._check_jwt_handling(_VulnerableClient(), "https://api.example.com/data")

    assert findings
    assert all("jwt validation weakness" in f.title.lower() for f in findings)
    assert all(f.severity.value == "critical" for f in findings)


def test_check_jwt_handling_no_finding_when_tokens_rejected():
    agent = ApiSecurityAgent()

    class _SafeClient:
        def get(self, url: str, headers: dict[str, str] | None = None) -> _FakeResponse:
            return _FakeResponse(status_code=401)

    findings = agent._check_jwt_handling(_SafeClient(), "https://api.example.com/data")

    assert findings == []


def test_check_exposed_jwt_claims_flags_alg_none():
    agent = ApiSecurityAgent()
    token = agent._craft_alg_none_jwt({"sub": "admin"})
    response = _FakeResponse(text=json.dumps({"access_token": token}))

    findings = agent._check_exposed_jwt_claims(response, "https://api.example.com/login")

    assert any("alg: none" in finding.title.lower() for finding in findings)


def test_check_exposed_jwt_claims_flags_missing_exp():
    import base64

    agent = ApiSecurityAgent()
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(b'{"sub":"admin"}').rstrip(b"=").decode()
    token = f"{header}.{payload}.somesignature"
    response = _FakeResponse(text=json.dumps({"access_token": token}))

    findings = agent._check_exposed_jwt_claims(response, "https://api.example.com/login")

    assert any("missing expiration" in finding.title.lower() for finding in findings)


def test_check_exposed_jwt_claims_no_finding_without_jwt():
    agent = ApiSecurityAgent()
    response = _FakeResponse(text=json.dumps({"status": "ok"}))

    assert agent._check_exposed_jwt_claims(response, "https://api.example.com/login") == []

