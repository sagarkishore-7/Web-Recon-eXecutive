"""Normalization helpers for httpx outputs."""

from __future__ import annotations

import json
from pathlib import Path

from wrx.models import AliveHost


def parse_httpx_jsonl(path: Path) -> list[AliveHost]:
    hosts: list[AliveHost] = []
    if not path.exists():
        return hosts

    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            # Fallback line parsing when JSON output isn't available.
            if line.startswith("http"):
                hosts.append(AliveHost(url=line, status_code=0))
            continue

        url = payload.get("url") or payload.get("input") or ""
        if not url:
            continue

        status = int(payload.get("status_code") or 0)
        title = payload.get("title")
        tech = payload.get("tech") or payload.get("technologies") or []
        if isinstance(tech, str):
            tech = [item.strip() for item in tech.split(",") if item.strip()]
        hosts.append(AliveHost(url=url, status_code=status, title=title, tech=list(tech)))

    deduped: dict[str, AliveHost] = {}
    for host in hosts:
        deduped[host.url] = host
    return list(deduped.values())
