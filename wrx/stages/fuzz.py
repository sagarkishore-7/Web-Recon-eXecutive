"""Endpoint fuzzing stage using ffuf."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Awaitable, Callable, Optional
from urllib.parse import urlparse

from wrx.models import DiscoveredURL
from wrx.normalize.ffuf import parse_ffuf_json
from wrx.workspace import write_json

RunCommand = Callable[[list[str], Path, int], Awaitable[int]]


DEFAULT_WORDS = [
    "admin",
    "login",
    "dashboard",
    "api",
    "robots.txt",
    "sitemap.xml",
    "health",
]


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


def _base_for_fuzz(url: str) -> Optional[str]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


async def execute(
    alive_hosts: list[str],
    raw_root: Path,
    data_root: Path,
    run_cmd: RunCommand,
    args: list[str],
    timeout: int,
    rate_limit: int,
    context_words: Optional[list[str]] = None,
) -> dict:
    stage = "fuzz"
    stage_dir = raw_root / stage
    stage_dir.mkdir(parents=True, exist_ok=True)

    log_path = stage_dir / "logs.txt"
    data_path = data_root / f"{stage}.json"

    bases = sorted({base for host in alive_hosts if (base := _base_for_fuzz(host))})
    if not bases:
        log_path.write_text("[wrx] no alive hosts available; stage skipped.\n", encoding="utf-8")
        payload = {
            "status": "skipped",
            "reason": "No alive hosts available for fuzzing",
            "urls": [],
        }
        write_json(data_path, payload)
        return payload

    if shutil.which("ffuf") is None:
        log_path.write_text("[wrx] ffuf not found in PATH; stage skipped.\n", encoding="utf-8")
        payload = {
            "status": "skipped",
            "reason": "ffuf not found in PATH",
            "urls": [],
        }
        write_json(data_path, payload)
        return payload

    wordlist_path = stage_dir / "default_wordlist.txt"
    if "-w" not in args:
        merged_words: list[str] = []
        seen_words: set[str] = set()
        for item in [*DEFAULT_WORDS, *(context_words or [])]:
            lowered = str(item).strip().lower()
            if not lowered or lowered in seen_words:
                continue
            seen_words.add(lowered)
            merged_words.append(lowered)
        wordlist_path.write_text("\n".join(merged_words) + "\n", encoding="utf-8")

    jobs: list[tuple[list[str], Path]] = []
    for index, base in enumerate(bases):
        output_path = stage_dir / f"ffuf_{index}.json"
        cmd = ["ffuf", "-u", f"{base}/FUZZ", "-of", "json", "-o", str(output_path)]
        if "-w" not in args:
            cmd.extend(["-w", str(wordlist_path)])
        if "-rate" not in args:
            cmd.extend(["-rate", str(rate_limit)])
        cmd.extend(list(args))
        jobs.append((cmd, output_path))

    exit_codes = await asyncio.gather(*[run_cmd(cmd, log_path, timeout) for cmd, _ in jobs])

    discovered: dict[str, DiscoveredURL] = {}
    for _, output_path in jobs:
        for item in parse_ffuf_json(output_path):
            discovered[item.url] = item

    payload = {
        "status": "completed" if all(code == 0 for code in exit_codes) else "error",
        "exit_code": 0 if all(code == 0 for code in exit_codes) else 1,
        "urls": _serialize_urls(list(discovered.values())),
        "context_words": [str(item) for item in (context_words or [])][:80],
    }
    write_json(data_path, payload)
    return payload
