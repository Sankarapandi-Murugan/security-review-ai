from security_review.infrastructure.scanners.red_team_agent import RedTeamAgent


def test_privilege_escalation_pattern_detected(tmp_path):
    (tmp_path / "ops.py").write_text("import os\ndef run():\n    os.system('sudo reboot')\n")

    findings = RedTeamAgent().execute(str(tmp_path))

    assert any("privilege escalation" in finding.title.lower() for finding in findings)


def test_lateral_movement_pattern_detected(tmp_path):
    (tmp_path / "config.py").write_text("INTERNAL_ADMIN_HOST = '10.0.5.23'\n")

    findings = RedTeamAgent().execute(str(tmp_path))

    assert any("lateral movement" in finding.title.lower() for finding in findings)


def test_chained_attack_path_detected(tmp_path):
    (tmp_path / "auth.py").write_text(
        "password = 'supersecret123'\n"
        "if user_password == pass_input:\n"
        "    eval(user_password)\n"
    )

    findings = RedTeamAgent().execute(str(tmp_path))

    assert any("chained attack path" in finding.title.lower() for finding in findings)


def test_no_findings_for_clean_code(tmp_path):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")

    findings = RedTeamAgent().execute(str(tmp_path))

    assert any("assessment completed" in finding.title.lower() for finding in findings)


def test_execute_none_target_returns_empty():
    assert RedTeamAgent().execute(None) == []
