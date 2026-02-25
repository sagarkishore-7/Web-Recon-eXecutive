"""Normalization helpers for ffuf outputs."""

from __future__ import annotations

import json
from pathlib import Path

from wrx.models import DiscoveredURL, now_utc_iso


def parse_ffuf_json(path: Path) -> list[DiscoveredURL]:
    urls: list[DiscoveredURL] = []
    if not path.exists():
        return urls

    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return urls

    results = payload.get("results") or []
    for item in results:
        url = item.get("url")
        if not isinstance(url, str) or not url:
            continue
        ts = item.get("timestamp") or now_utc_iso()
        urls.append(DiscoveredURL(url=url, source_stage="fuzz", discovered_at=ts))

    deduped: dict[str, DiscoveredURL] = {}
    for item in urls:
        deduped[item.url] = item
    return list(deduped.values())
