"""Preflight checks for WRX environments and local demo readiness."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from wrx import __version__

JUICE_SHOP_URL = "http://localhost:3000"
JUICE_SHOP_FALLBACK_URL = "http://127.0.0.1:3000"
JUICE_SHOP_DOCKER_CMD = (
    "docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop"
)
ZAP_DOCKER_IMAGE = "owasp/zap2docker-stable"
ZAP_DOCKER_IMAGE_FALLBACK = "zaproxy/zap-stable"


@dataclass
class HealthCheck:
    """Single health-check result."""

    name: str
    required: bool
    ok: bool
    details: str
    fix: str

    @property
    def status(self) -> str:
        return "PASS" if self.ok else "FAIL"


def _check_python_version() -> HealthCheck:
    version_info = sys.version_info
    ok = version_info >= (3, 9)
    details = f"{version_info.major}.{version_info.minor}.{version_info.micro}"
    fix = "Install Python 3.9+ and recreate your virtual environment."
    return HealthCheck(
        name="Python version",
        required=True,
        ok=ok,
        details=details,
        fix=fix,
    )


def _check_wrx_version() -> HealthCheck:
    ok = bool(__version__)
    return HealthCheck(
        name="WRX version",
        required=True,
        ok=ok,
        details=__version__ if ok else "version not set",
        fix="Reinstall WRX: pip install -e .",
    )


def _check_write_permissions(base_dir: Path) -> HealthCheck:
    try:
        base_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            prefix=".wrx-doctor-",
            suffix=".tmp",
            dir=base_dir,
            delete=True,
        ) as handle:
            handle.write("wrx-doctor")
        return HealthCheck(
            name="Workspace write access",
            required=True,
            ok=True,
            details=str(base_dir),
            fix="Ensure write permissions for current working directory.",
        )
    except OSError as exc:
        return HealthCheck(
            name="Workspace write access",
            required=True,
            ok=False,
            details=f"{base_dir} ({exc})",
            fix="Run in a writable directory or update permissions.",
        )


def _check_tool(tool: str, required: bool, fix: str) -> HealthCheck:
    path = shutil.which(tool)
    return HealthCheck(
        name=f"Tool: {tool}",
        required=required,
        ok=path is not None,
        details=path or "not found on PATH",
        fix=fix,
    )


def _check_httpx_tool() -> HealthCheck:
    primary = shutil.which("httpx")
    candidates: list[str] = []
    if primary:
        candidates.append(primary)
    for alt in ("/opt/homebrew/bin/httpx", "/usr/local/bin/httpx"):
        if Path(alt).exists():
            candidates.append(alt)

    if not candidates:
        return HealthCheck(
            name="Tool: httpx",
            required=True,
            ok=False,
            details="not found on PATH",
            fix="Install ProjectDiscovery httpx: https://github.com/projectdiscovery/httpx",
        )

    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        ok, output = _run_process([candidate, "-h"], timeout=4.0)
        text = output.lower()
        looks_like_pd = "-l, -list" in text or "input file containing list of hosts to process" in text
        if ok and looks_like_pd:
            details = candidate
            if primary and primary != candidate:
                details = f"{candidate} (using fallback; PATH resolves to {primary})"
            return HealthCheck(
                name="Tool: httpx",
                required=True,
                ok=True,
                details=details,
                fix="-",
            )

    return HealthCheck(
        name="Tool: httpx",
        required=True,
        ok=False,
        details=f"{primary or candidates[0]} (non-ProjectDiscovery httpx CLI detected)",
        fix=(
            "Install ProjectDiscovery httpx and ensure it appears on PATH before Python's httpx CLI."
        ),
    )


def _run_process(cmd: list[str], timeout: float = 5.0) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)

    output = (result.stdout or result.stderr or "").strip()
    return result.returncode == 0, output


def _summarize_detail(output: str, max_chars: int = 180) -> str:
    text = " ".join(output.splitlines()).strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def _check_docker_daemon() -> HealthCheck:
    docker_path = shutil.which("docker")
    if docker_path is None:
        return HealthCheck(
            name="Docker daemon",
            required=True,
            ok=False,
            details="docker binary not found",
            fix="Install Docker Desktop: https://www.docker.com/products/docker-desktop/",
        )

    ok, output = _run_process(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=8.0)
    if ok:
        details = output or "reachable"
    else:
        details = _summarize_detail(output) or "docker daemon unreachable"
    return HealthCheck(
        name="Docker daemon",
        required=True,
        ok=ok,
        details=details,
        fix="Start Docker Desktop and verify 'docker info' works.",
    )


def _check_zap_image(image: str, fallback_image: str) -> HealthCheck:
    docker_path = shutil.which("docker")
    if docker_path is None:
        return HealthCheck(
            name="ZAP image readiness",
            required=True,
            ok=False,
            details=f"docker missing (image: {image})",
            fix="Install Docker Desktop and rerun wrx doctor.",
        )

    daemon_ok, daemon_output = _run_process(["docker", "info"], timeout=8.0)
    if not daemon_ok:
        return HealthCheck(
            name="ZAP image readiness",
            required=True,
            ok=False,
            details="docker daemon unreachable",
            fix="Start Docker Desktop and verify 'docker info' works.",
        )

    image_ok, _ = _run_process(["docker", "image", "inspect", image], timeout=8.0)
    if image_ok:
        return HealthCheck(
            name="ZAP image readiness",
            required=True,
            ok=True,
            details=f"{image} is available locally",
            fix="",
        )

    fallback_ok, _ = _run_process(["docker", "image", "inspect", fallback_image], timeout=8.0)
    if fallback_ok:
        return HealthCheck(
            name="ZAP image readiness",
            required=True,
            ok=True,
            details=f"{fallback_image} is available locally (legacy image fallback enabled)",
            fix="",
        )

    return HealthCheck(
        name="ZAP image readiness",
        required=True,
        ok=True,
        details=(
            f"{image} not present locally; it will be pulled on first demo run "
            f"(fallback: {fallback_image})"
        ),
        fix="Run once with network access to allow Docker image pull.",
    )


def check_juice_shop_reachable(url: str = JUICE_SHOP_URL, timeout: float = 3.0) -> HealthCheck:
    """Check whether Juice Shop is reachable on localhost."""
    attempts: list[tuple[str, str]] = []
    urls = [url]
    if url == JUICE_SHOP_URL:
        urls.append(JUICE_SHOP_FALLBACK_URL)

    for candidate in urls:
        try:
            with urllib.request.urlopen(candidate, timeout=timeout) as response:
                status = int(getattr(response, "status", 0) or 0)
            if 200 <= status < 500:
                return HealthCheck(
                    name="Juice Shop reachable",
                    required=True,
                    ok=True,
                    details=f"{candidate} (HTTP {status})",
                    fix=f"Start Juice Shop locally: {JUICE_SHOP_DOCKER_CMD}",
                )
            attempts.append((candidate, f"HTTP {status}"))
        except urllib.error.URLError as exc:
            attempts.append((candidate, str(exc.reason)))
        except Exception as exc:  # pragma: no cover - defensive fallback
            attempts.append((candidate, str(exc)))

    details = "; ".join(f"{candidate} ({reason})" for candidate, reason in attempts)

    return HealthCheck(
        name="Juice Shop reachable",
        required=True,
        ok=False,
        details=details,
        fix=f"Start Juice Shop locally: {JUICE_SHOP_DOCKER_CMD}",
    )


def run_doctor_checks(base_dir: Path) -> list[HealthCheck]:
    """Run all doctor checks."""
    checks: list[HealthCheck] = [
        _check_python_version(),
        _check_wrx_version(),
        _check_write_permissions(base_dir),
        _check_tool("docker", required=True, fix="Install Docker Desktop: https://www.docker.com/products/docker-desktop/"),
        _check_docker_daemon(),
        _check_zap_image(ZAP_DOCKER_IMAGE, ZAP_DOCKER_IMAGE_FALLBACK),
        _check_tool("subfinder", required=True, fix="Install from ProjectDiscovery: https://github.com/projectdiscovery/subfinder"),
        _check_httpx_tool(),
        _check_tool("katana", required=True, fix="Install from ProjectDiscovery: https://github.com/projectdiscovery/katana"),
        _check_tool("nuclei", required=True, fix="Install from ProjectDiscovery: https://github.com/projectdiscovery/nuclei"),
        _check_tool("ffuf", required=True, fix="Install FFUF: https://github.com/ffuf/ffuf"),
        check_juice_shop_reachable(),
    ]
    return checks


def strict_failures(checks: list[HealthCheck]) -> int:
    """Count failed required checks."""
    return sum(1 for item in checks if item.required and not item.ok)
