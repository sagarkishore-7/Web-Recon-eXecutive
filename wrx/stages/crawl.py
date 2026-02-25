"""URL crawling stage using katana."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Awaitable, Callable

from wrx.models import DiscoveredURL
from wrx.normalize.katana import parse_katana_jsonl
from wrx.workspace import write_json

RunCommand = Callable[[list[str], Path, int], Awaitable[int]]


def _serialize_urls(urls: list[DiscoveredURL]) -> list[dict]:
    return [
        {
            "url": item.url,
            "source_stage": item.source_stage,
            "discovered_at": item.discovered_at,
            "hash": item.hash,
        }
        for item in urls
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


def _normalize_output_flags(args: list[str]) -> list[str]:
    normalized = [item for item in args if item not in {"-jsonl", "-json"}]
    if _tool_supports_flag("katana", "-jsonl"):
        normalized.append("-jsonl")
    elif _tool_supports_flag("katana", "-json"):
        normalized.append("-json")
    return normalized


async def execute(
    alive_hosts: list[str],
    raw_root: Path,
    data_root: Path,
    run_cmd: RunCommand,
    args: list[str],
    timeout: int,
) -> dict:
    stage = "crawl"
    stage_dir = raw_root / stage
    stage_dir.mkdir(parents=True, exist_ok=True)

    log_path = stage_dir / "logs.txt"
    targets_path = stage_dir / "targets.txt"
    output_path = stage_dir / "katana.jsonl"
    data_path = data_root / f"{stage}.json"

    targets = sorted({item.strip() for item in alive_hosts if item.strip()})
    targets_path.write_text("\n".join(targets) + ("\n" if targets else ""), encoding="utf-8")
    if not targets:
        log_path.write_text("[wrx] no alive hosts available; stage skipped.\n", encoding="utf-8")
        payload = {
            "status": "skipped",
            "reason": "No alive hosts to crawl",
            "urls": [],
        }
        write_json(data_path, payload)
        return payload

    if shutil.which("katana") is None:
        log_path.write_text("[wrx] katana not found in PATH; stage skipped.\n", encoding="utf-8")
        payload = {
            "status": "skipped",
            "reason": "katana not found in PATH",
            "urls": [],
        }
        write_json(data_path, payload)
        return payload

    cmd_args = _normalize_output_flags(list(args))
    cmd = ["katana", "-list", str(targets_path), "-o", str(output_path)] + cmd_args
    exit_code = await run_cmd(cmd, log_path, timeout)

    urls = parse_katana_jsonl(output_path)
    payload = {
        "status": "completed" if exit_code == 0 else "error",
        "exit_code": exit_code,
        "urls": _serialize_urls(urls),
    }
    write_json(data_path, payload)
    return payload
