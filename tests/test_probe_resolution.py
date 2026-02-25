from pathlib import Path

from wrx.stages import probe


def test_resolve_httpx_binary_prefers_projectdiscovery_fallback(monkeypatch) -> None:
    monkeypatch.setattr(probe.shutil, "which", lambda _: "/tmp/venv/bin/httpx")

    existing = {"/opt/homebrew/bin/httpx"}
    monkeypatch.setattr(Path, "exists", lambda self: str(self) in existing, raising=False)
    monkeypatch.setattr(
        probe,
        "_is_projectdiscovery_httpx",
        lambda binary: binary == "/opt/homebrew/bin/httpx",
    )

    assert probe._resolve_httpx_binary() == "/opt/homebrew/bin/httpx"


def test_resolve_httpx_binary_returns_none_without_projectdiscovery(monkeypatch) -> None:
    monkeypatch.setattr(probe.shutil, "which", lambda _: "/tmp/venv/bin/httpx")
    monkeypatch.setattr(Path, "exists", lambda self: False, raising=False)
    monkeypatch.setattr(probe, "_is_projectdiscovery_httpx", lambda _: False)

    assert probe._resolve_httpx_binary() is None
