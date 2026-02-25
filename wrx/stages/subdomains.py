"""Subdomain enumeration stage."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Awaitable, Callable, Optional
from urllib.parse import urlparse

from wrx.workspace import write_json

RunCommand = Callable[[list[str], Path, int], Awaitable[int]]


def _parse_subfinder_output(path: Path) -> list[str]:
    subdomains: set[str] = set()
    if not path.exists():
        return []

    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            host = payload.get("host") or payload.get("input")
            if host:
                subdomains.add(str(host).strip())
        except json.JSONDecodeError:
            if "." in line and " " not in line:
                subdomains.add(line)

    return sorted(subdomains)


def _normalize_target_for_subfinder(target: str) -> Optional[str]:
    parsed = urlparse(target)
    host = (parsed.hostname or "").strip().lower()
    if host:
        if host in {"localhost", "127.0.0.1", "::1"}:
            return None
        return host

    value = target.strip().lower()
    if value in {"localhost", "127.0.0.1", "::1"}:
        return None
    return value or None


async def execute(
    target: str,
    raw_root: Path,
    data_root: Path,
    run_cmd: RunCommand,
    args: list[str],
    timeout: int,
) -> dict:
    stage = "subdomains"
    stage_dir = raw_root / stage
    stage_dir.mkdir(parents=True, exist_ok=True)

    log_path = stage_dir / "logs.txt"
    output_path = stage_dir / "subfinder.jsonl"
    data_path = data_root / f"{stage}.json"

    if shutil.which("subfinder") is None:
        log_path.write_text("[wrx] subfinder not found in PATH; stage skipped.\n", encoding="utf-8")
        payload = {
            "status": "skipped",
            "reason": "subfinder not found in PATH",
            "subdomains": [],
        }
        write_json(data_path, payload)
        return payload

    normalized_target = _normalize_target_for_subfinder(target)
    if not normalized_target:
        log_path.write_text("[wrx] subfinder skipped for localhost target.\n", encoding="utf-8")
        payload = {
            "status": "skipped",
            "reason": "subfinder is not applicable to localhost targets",
            "subdomains": [],
        }
        write_json(data_path, payload)
        return payload

    cmd = ["subfinder", "-d", normalized_target, "-oJ", "-o", str(output_path)] + list(args)
    exit_code = await run_cmd(cmd, log_path, timeout)

    subdomains = _parse_subfinder_output(output_path)
    payload = {
        "status": "completed" if exit_code == 0 else "error",
        "exit_code": exit_code,
        "subdomains": subdomains,
    }
    write_json(data_path, payload)
    return payload
