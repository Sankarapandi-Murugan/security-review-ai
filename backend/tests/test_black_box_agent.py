from security_review.infrastructure.scanners.black_box_agent import BlackBoxAgent


class _FakeResponse:
    def __init__(self, text: str = "", headers: dict[str, str] | None = None) -> None:
        self.text = text
        self.headers = headers or {}


def test_check_security_headers_flags_missing_headers():
    agent = BlackBoxAgent()
    response = _FakeResponse(headers={"content-type": "text/html"})

    findings = agent._check_security_headers(response, "https://example.com")

    assert findings
    assert "Content-Security-Policy" in findings[0].description


def test_check_security_headers_no_finding_when_all_present():
    agent = BlackBoxAgent()
    headers = {
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "strict-transport-security": "max-age=63072000",
        "x-content-type-options": "nosniff",
    }
    response = _FakeResponse(headers=headers)

    assert agent._check_security_headers(response, "https://example.com") == []


def test_check_csrf_forms_flags_form_without_token():
    agent = BlackBoxAgent()
    html = '<form method="post" action="/transfer"><input name="amount"/></form>'

    findings = agent._check_csrf_forms(html, "https://example.com/transfer")

    assert findings
    assert "CSRF" in findings[0].title


def test_check_csrf_forms_no_finding_with_token_present():
    agent = BlackBoxAgent()
    html = '<form method="post"><input type="hidden" name="csrf_token" value="abc"/></form>'

    assert agent._check_csrf_forms(html, "https://example.com/transfer") == []


def test_check_reflected_xss_detects_unescaped_reflection():
    from urllib.parse import parse_qs, urlparse

    agent = BlackBoxAgent()
    url = "https://example.com/search?q=test"

    class _ReflectingClient:
        def get(self, probe_url: str) -> _FakeResponse:
            value = parse_qs(urlparse(probe_url).query)["q"][0]
            return _FakeResponse(text=f"<div>results for {value}</div>")

    findings = agent._check_reflected_xss(_ReflectingClient(), url)

    assert findings
    assert "XSS" in findings[0].title


def test_check_sql_error_signatures_detects_db_error():
    agent = BlackBoxAgent()
    url = "https://example.com/item?id=1"

    class _ErrorClient:
        def get(self, probe_url: str) -> _FakeResponse:
            return _FakeResponse(text="You have an error in your SQL syntax near '''")

    findings = agent._check_sql_error_signatures(_ErrorClient(), url)

    assert findings
    assert "SQL Injection" in findings[0].title


def test_execute_without_authorization_skips_deep_assessment():
    agent = BlackBoxAgent()

    findings = agent.execute("https://127.0.0.1/", authorized=False)

    assert any("authorization" in finding.title.lower() for finding in findings)


def test_execute_none_target_returns_empty():
    assert BlackBoxAgent().execute(None) == []
