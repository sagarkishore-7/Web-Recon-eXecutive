"""Normalization helpers for OWASP ZAP baseline JSON output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from wrx.models import ZapFinding


_RISK_CODE_MAP = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "High",
}


def _trim(value: Any, max_len: int = 240) -> str:
    if value is None:
        return ""
    text = str(value).strip().replace("\n", " ")
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _extract_risk(alert: dict[str, Any]) -> str:
    riskdesc = str(alert.get("riskdesc") or "").strip()
    if riskdesc:
        token = riskdesc.split("(", 1)[0].strip()
        if token:
            return token

    risk = str(alert.get("risk") or "").strip()
    if risk:
        return risk

    risk_code = str(alert.get("riskcode") or "").strip()
    return _RISK_CODE_MAP.get(risk_code, "Informational")


def _extract_url(alert: dict[str, Any], site_name: str) -> str:
    direct = str(alert.get("url") or "").strip()
    if direct:
        return direct

    instances = alert.get("instances")
    if isinstance(instances, list):
        for item in instances:
            if not isinstance(item, dict):
                continue
            uri = str(item.get("uri") or "").strip()
            if uri:
                return uri

    return site_name


def _extract_evidence(alert: dict[str, Any]) -> str:
    direct = str(alert.get("evidence") or "").strip()
    if direct:
        return _trim(direct)

    instances = alert.get("instances")
    if isinstance(instances, list):
        for item in instances:
            if not isinstance(item, dict):
                continue
            evidence = str(item.get("evidence") or "").strip()
            if evidence:
                return _trim(evidence)

    return ""


def _extract_instances_count(alert: dict[str, Any]) -> int:
    count_raw = alert.get("count")
    if isinstance(count_raw, (int, float)):
        return int(count_raw)
    if isinstance(count_raw, str) and count_raw.isdigit():
        return int(count_raw)

    instances = alert.get("instances")
    if isinstance(instances, list):
        return len(instances)

    return 0


def _collect_alert_groups(payload: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    grouped: list[tuple[str, dict[str, Any]]] = []

    alerts = payload.get("alerts")
    if isinstance(alerts, list):
        for alert in alerts:
            if isinstance(alert, dict):
                grouped.append(("", alert))

    sites = payload.get("site")
    if isinstance(sites, dict):
        sites = [sites]

    if isinstance(sites, list):
        for site in sites:
            if not isinstance(site, dict):
                continue
            site_name = str(site.get("@name") or site.get("name") or "").strip()
            site_alerts = site.get("alerts")
            if not isinstance(site_alerts, list):
                continue
            for alert in site_alerts:
                if isinstance(alert, dict):
                    grouped.append((site_name, alert))

    return grouped


def parse_zap_json(path: Path) -> list[ZapFinding]:
    """Parse ZAP baseline JSON report into normalized findings."""
    if not path.exists():
        return []

    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return []

    if not isinstance(payload, dict):
        return []

    findings: list[ZapFinding] = []

    for site_name, alert in _collect_alert_groups(payload):
        plugin_id = str(alert.get("pluginid") or alert.get("alertRef") or alert.get("id") or "unknown")
        alert_name = str(alert.get("alert") or alert.get("name") or "unknown")
        risk = _extract_risk(alert)
        confidence = str(alert.get("confidence") or alert.get("confidenceDesc") or "Unknown")
        finding = ZapFinding(
            plugin_id=plugin_id,
            alert=alert_name,
            risk=risk,
            confidence=confidence,
            url=_extract_url(alert, site_name),
            evidence=_extract_evidence(alert),
            description=_trim(alert.get("desc")),
            solution=_trim(alert.get("solution")),
            reference=_trim(alert.get("reference")),
            cweid=str(alert.get("cweid") or ""),
            wascid=str(alert.get("wascid") or ""),
            instances=_extract_instances_count(alert),
        )
        findings.append(finding)

    deduped: dict[str, ZapFinding] = {}
    for item in findings:
        deduped[item.hash] = item
    return list(deduped.values())
