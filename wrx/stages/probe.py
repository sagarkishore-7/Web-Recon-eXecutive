"""Host probing stage using httpx."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Awaitable, Callable, Optional

from wrx.models import AliveHost
from wrx.normalize.httpx import parse_httpx_jsonl
from wrx.workspace import write_json

RunCommand = Callable[[list[str], Path, int], Awaitable[int]]


def _serialize_alive_hosts(hosts: list[AliveHost]) -> list[dict]:
    return [
        {
            "url": host.url,
            "status_code": host.status_code,
            "title": host.title,
            "tech": host.tech,
            "hash": host.hash,
        }
        for host in hosts
    ]


def _tool_supports_flag(tool: str, flag: str) -> bool:
    for help_flag in ("-h", "--help"):
        try:
            result = subprocess.run(
                [tool, help_flag],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue

        output = f"{result.stdout}\n{result.stderr}"
        if flag in output:
            return True
    return False


def _is_projectdiscovery_httpx(binary: str) -> bool:
    try:
        result = subprocess.run(
            [binary, "-h"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False

    output = f"{result.stdout}\n{result.stderr}"
    return "-l, -list" in output or "input file containing list of hosts to process" in output


def _resolve_httpx_binary() -> Optional[str]:
    candidates: list[str] = []
    primary = shutil.which("httpx")
    if primary:
        candidates.append(primary)

    for alt in ("/opt/homebrew/bin/httpx", "/usr/local/bin/httpx"):
        if Path(alt).exists():
            candidates.append(alt)

    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if _is_projectdiscovery_httpx(candidate):
            return candidate

    return None


def _normalize_output_flags(binary: str, args: list[str]) -> list[str]:
    normalized = [item for item in args if item not in {"-json", "-j"}]
    if _tool_supports_flag(binary, "-json"):
        normalized.append("-json")
    elif _tool_supports_flag(binary, "-j"):
        normalized.append("-j")
    return normalized


async def execute(
    target: str,
    hosts: list[str],
    seed_hosts: Optional[list[str]],
    raw_root: Path,
    data_root: Path,
    run_cmd: RunCommand,
    args: list[str],
    timeout: int,
) -> dict:
    stage = "probe"
    stage_dir = raw_root / stage
    stage_dir.mkdir(parents=True, exist_ok=True)

    log_path = stage_dir / "logs.txt"
    targets_path = stage_dir / "targets.txt"
    output_path = stage_dir / "httpx.jsonl"
    data_path = data_root / f"{stage}.json"

    candidates = sorted({item.strip() for item in hosts if item.strip()})
    if not candidates:
        candidates = sorted({item.strip() for item in (seed_hosts or []) if item.strip()})
    if not candidates:
        candidates = [target]
    targets_path.write_text("\n".join(candidates) + "\n", encoding="utf-8")

    httpx_binary = _resolve_httpx_binary()
    if not httpx_binary:
        log_path.write_text(
            "[wrx] ProjectDiscovery httpx not found; stage skipped.\n"
            "[wrx] Install pd httpx and ensure it appears on PATH before Python's httpx CLI.\n",
            encoding="utf-8",
        )
        payload = {
            "status": "skipped",
            "reason": "ProjectDiscovery httpx not found on PATH",
            "alive_hosts": [],
        }
        write_json(data_path, payload)
        return payload

    cmd_args = _normalize_output_flags(httpx_binary, list(args))
    cmd = [httpx_binary, "-l", str(targets_path), "-o", str(output_path)] + cmd_args
    exit_code = await run_cmd(cmd, log_path, timeout)

    alive_hosts = parse_httpx_jsonl(output_path)
    payload = {
        "status": "completed" if exit_code == 0 else "error",
        "exit_code": exit_code,
        "alive_hosts": _serialize_alive_hosts(alive_hosts),
    }
    write_json(data_path, payload)
    return payload
