from security_review.infrastructure.scanners.blue_team_agent import BlueTeamAgent


def test_detects_brute_force_login_attempts(tmp_path):
    log_file = tmp_path / "auth.log"
    lines = ["Failed password for admin from 203.0.113.5 port 22 ssh2" for _ in range(6)]
    log_file.write_text("\n".join(lines))

    findings = BlueTeamAgent().execute(str(tmp_path))

    assert any("brute-force" in finding.title.lower() for finding in findings)
    assert any("incident summary" in finding.title.lower() for finding in findings)


def test_detects_injection_payload_in_access_log(tmp_path):
    log_file = tmp_path / "access.log"
    log_file.write_text(
        "203.0.113.9 - - [01/Aug/2026:12:00:00] \"GET /products?id=1' UNION SELECT username,password FROM users-- HTTP/1.1\" 200\n"
    )

    findings = BlueTeamAgent().execute(str(tmp_path))

    assert any("attack payload" in finding.title.lower() for finding in findings)


def test_detects_privileged_command_in_logs(tmp_path):
    log_file = tmp_path / "audit.log"
    log_file.write_text("2026-08-01T12:00:00 user=deploy cmd='chmod 777 /var/www'\n")

    findings = BlueTeamAgent().execute(str(tmp_path))

    assert any("privileged command" in finding.title.lower() for finding in findings)


def test_detects_scanner_activity(tmp_path):
    log_file = tmp_path / "access.log"
    lines = [
        "198.51.100.7 - - \"GET /wp-login.php HTTP/1.1\" 404",
        "198.51.100.7 - - \"GET /.env HTTP/1.1\" 404",
        "198.51.100.7 - - \"GET /.git/config HTTP/1.1\" 404",
    ]
    log_file.write_text("\n".join(lines))

    findings = BlueTeamAgent().execute(str(tmp_path))

    assert any("vulnerability scanning" in finding.title.lower() for finding in findings)


def test_no_suspicious_activity_reports_baseline_recommendation(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("2026-08-01T12:00:00 INFO request completed successfully\n")

    findings = BlueTeamAgent().execute(str(tmp_path))

    assert any("no suspicious activity" in finding.title.lower() for finding in findings)


def test_no_log_files_found_does_not_add_log_findings(tmp_path):
    (tmp_path / "main.py").write_text("def add(a, b):\n    return a + b\n")

    findings = BlueTeamAgent().execute(str(tmp_path))

    assert not any("log analysis" in finding.title.lower() for finding in findings)


def test_execute_none_target_returns_empty():
    assert BlueTeamAgent().execute(None) == []
