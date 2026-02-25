"""Normalization helpers for nuclei outputs."""

from __future__ import annotations

import json
from pathlib import Path

from wrx.models import NucleiFinding, now_utc_iso


def parse_nuclei_jsonl(path: Path) -> list[NucleiFinding]:
    findings: list[NucleiFinding] = []
    if not path.exists():
        return findings

    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue

        template_id = payload.get("template-id") or payload.get("templateID") or "unknown"
        info = payload.get("info") or {}
        severity = info.get("severity") or payload.get("severity") or "unknown"
        name = info.get("name") or payload.get("name") or template_id
        matched_at = payload.get("matched-at") or payload.get("host") or payload.get("matched") or ""
        if not matched_at:
            continue

        extracted = payload.get("extracted-results") or payload.get("extracted_results") or []
        if isinstance(extracted, str):
            extracted = [extracted]

        findings.append(
            NucleiFinding(
                template_id=str(template_id),
                severity=str(severity),
                name=str(name),
                matched_at=str(matched_at),
                extracted_results=[str(x) for x in extracted],
                timestamp=str(payload.get("timestamp") or now_utc_iso()),
            )
        )

    deduped: dict[str, NucleiFinding] = {}
    for item in findings:
        deduped[item.hash] = item
    return list(deduped.values())
