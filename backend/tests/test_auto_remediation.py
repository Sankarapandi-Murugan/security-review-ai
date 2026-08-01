from security_review.infrastructure.scanners.auto_remediation_agent import AutoRemediationAgent


def test_auto_remediation_patches_missing_timeout(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "client.py").write_text(
        "import requests\n\ndef fetch(url):\n    return requests.get(url)\n"
    )

    agent = AutoRemediationAgent()
    findings = agent.execute(str(target))

    assert any("timeout" in finding.title.lower() for finding in findings)
    patched = (target / "client.py").read_text()
    assert "timeout=10" in patched


def test_auto_remediation_preserves_existing_timeout(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    original = "import requests\n\ndef fetch(url):\n    return requests.get(url, timeout=5)\n"
    (target / "client.py").write_text(original)

    agent = AutoRemediationAgent()
    findings = agent.execute(str(target))

    assert any("no auto-fixable" in finding.title.lower() for finding in findings)
    assert (target / "client.py").read_text() == original


def test_auto_remediation_no_fixable_findings(tmp_path):
    target = tmp_path / "clean"
    target.mkdir()
    (target / "ok.py").write_text("def add(a, b):\n    return a + b\n")

    agent = AutoRemediationAgent()
    findings = agent.execute(str(target))

    assert any("no auto-fixable" in finding.title.lower() for finding in findings)


def test_auto_remediation_missing_target():
    agent = AutoRemediationAgent()
    assert agent.execute(None) == []


def test_auto_remediation_missing_path(tmp_path):
    agent = AutoRemediationAgent()
    findings = agent.execute(str(tmp_path / "does-not-exist"))
    assert len(findings) == 1
    assert "not found" in findings[0].title.lower()
