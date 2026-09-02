"""Tests."""

from pathlib import Path

from python_security_analyzer.core import analyze_file

FIXTURES = Path(__file__).resolve().parent.parent / "sample_data"


class TestPythonSecurityAnalyzer:
    def test_finds_issues(self) -> None:
        r = analyze_file(FIXTURES / "sample_vuln.py")
        assert len(r.issues) >= 3

    def test_finds_eval(self) -> None:
        r = analyze_file(FIXTURES / "sample_vuln.py")
        assert any(i.issue == "dangerous_eval" for i in r.issues)

    def test_finds_pickle(self) -> None:
        r = analyze_file(FIXTURES / "sample_vuln.py")
        assert any(i.issue == "insecure_deserialization" for i in r.issues)
