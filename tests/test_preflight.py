from pathlib import Path

from wrx import preflight
from wrx.preflight import run_doctor_checks


def test_doctor_checks_return_expected_rows(tmp_path: Path) -> None:
    checks = run_doctor_checks(tmp_path)
    names = {item.name for item in checks}

    assert "Python version" in names
    assert "WRX version" in names
    assert "Workspace write access" in names
    assert "Docker daemon" in names
    assert "ZAP image readiness" in names
    assert "Juice Shop reachable" in names


def test_httpx_check_uses_projectdiscovery_fallback(monkeypatch) -> None:
    monkeypatch.setattr(preflight.shutil, "which", lambda _: "/tmp/venv/bin/httpx")

    existing = {"/opt/homebrew/bin/httpx"}
    monkeypatch.setattr(Path, "exists", lambda self: str(self) in existing, raising=False)

    def fake_run_process(cmd: list[str], timeout: float = 5.0) -> tuple[bool, str]:
        if cmd[0] == "/tmp/venv/bin/httpx":
            return True, "HTTPX 🦋"
        if cmd[0] == "/opt/homebrew/bin/httpx":
            return True, "-l, -list string input file containing list of hosts to process"
        return False, ""

    monkeypatch.setattr(preflight, "_run_process", fake_run_process)
    check = preflight._check_httpx_tool()

    assert check.ok is True
    assert "/opt/homebrew/bin/httpx" in check.details
