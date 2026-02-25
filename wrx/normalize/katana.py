"""Normalization helpers for katana outputs."""

from __future__ import annotations

import json
from pathlib import Path

from wrx.models import DiscoveredURL, now_utc_iso


def parse_katana_jsonl(path: Path) -> list[DiscoveredURL]:
    urls: list[DiscoveredURL] = []
    if not path.exists():
        return urls

    now = now_utc_iso()
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            if line.startswith("http"):
                urls.append(DiscoveredURL(url=line, source_stage="crawl", discovered_at=now))
            continue

        url = payload.get("url") or payload.get("endpoint") or payload.get("request")
        if isinstance(url, dict):
            url = url.get("endpoint") or url.get("url")
        if not isinstance(url, str) or not url:
            continue

        discovered_at = payload.get("timestamp") or now
        urls.append(DiscoveredURL(url=url, source_stage="crawl", discovered_at=discovered_at))

    deduped: dict[str, DiscoveredURL] = {}
    for item in urls:
        deduped[item.url] = item
    return list(deduped.values())
