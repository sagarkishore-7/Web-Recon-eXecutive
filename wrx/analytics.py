"""Analytics helpers for WRX historical and graph-oriented insights."""

from __future__ import annotations

from collections import Counter
from typing import Any, Optional
from urllib.parse import urlparse


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _host_key(value: str) -> str:
    parsed = urlparse(str(value or "").strip())
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    if value.startswith("http://") or value.startswith("https://"):
        return value.rstrip("/")
    return ""


def build_preset_trends(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Group run count history by preset and add aggregate rollups."""
    chronological = list(reversed(runs))
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in chronological:
        preset = str(row.get("preset", "unknown"))
        grouped.setdefault(preset, []).append(
            {
                "run_id": str(row.get("run_id", "")),
                "timestamp": str(row.get("timestamp", "")),
                "counts": row.get("counts", {}),
            }
        )

    rollups: dict[str, dict[str, Any]] = {}
    for preset, points in grouped.items():
        totals = Counter()
        for point in points:
            totals.update({k: _safe_int(v) for k, v in (point.get("counts") or {}).items()})
        count = max(1, len(points))
        rollups[preset] = {
            "runs": len(points),
            "latest": points[-1]["counts"] if points else {},
            "averages": {key: round(value / count, 2) for key, value in totals.items()},
        }

    return {"series": grouped, "rollups": rollups}


def build_coverage_drift(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compute count deltas between consecutive historical runs."""
    chronological = list(reversed(runs))
    if len(chronological) < 2:
        return []

    rows: list[dict[str, Any]] = []
    for idx in range(1, len(chronological)):
        previous = chronological[idx - 1]
        current = chronological[idx]
        previous_counts = previous.get("counts", {})
        current_counts = current.get("counts", {})

        delta_alive = _safe_int(current_counts.get("alive_hosts")) - _safe_int(previous_counts.get("alive_hosts"))
        delta_urls = _safe_int(current_counts.get("urls")) - _safe_int(previous_counts.get("urls"))
        delta_nuclei = _safe_int(current_counts.get("nuclei_findings")) - _safe_int(previous_counts.get("nuclei_findings"))
        delta_zap = _safe_int(current_counts.get("zap_findings")) - _safe_int(previous_counts.get("zap_findings"))

        rows.append(
            {
                "from_run": str(previous.get("run_id", "")),
                "to_run": str(current.get("run_id", "")),
                "from_preset": str(previous.get("preset", "unknown")),
                "to_preset": str(current.get("preset", "unknown")),
                "delta_alive_hosts": delta_alive,
                "delta_urls": delta_urls,
                "delta_nuclei": delta_nuclei,
                "delta_zap": delta_zap,
                "delta_surface": delta_alive + delta_urls,
                "delta_findings": delta_nuclei + delta_zap,
            }
        )
    return rows


def build_asset_graph(
    summary: dict[str, Any],
    include_types: Optional[set[str]] = None,
    query: str = "",
    max_nodes: int = 500,
) -> dict[str, Any]:
    """Build a lightweight asset graph from normalized summary content."""
    include_types = {item.lower() for item in (include_types or set()) if item}
    needle = query.strip().lower()

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, str]] = {}

    def allow(node_type: str) -> bool:
        return not include_types or node_type in include_types

    def add_node(node_id: str, node_type: str, label: str, detail: str = "") -> None:
        if not allow(node_type):
            return
        if len(nodes) >= max_nodes and node_id not in nodes:
            return
        if needle:
            combined = f"{label} {detail} {node_type}".lower()
            if needle not in combined:
                return
        existing = nodes.get(node_id)
        if existing:
            existing["weight"] = _safe_int(existing.get("weight")) + 1
            return
        nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "label": label,
            "detail": detail,
            "weight": 1,
        }

    def add_edge(source: str, target: str, relation: str) -> None:
        if source == target:
            return
        if source not in nodes or target not in nodes:
            return
        key = f"{source}->{target}:{relation}"
        edges[key] = {"source": source, "target": target, "relation": relation}

    alive_hosts = summary.get("alive_hosts", [])
    urls = summary.get("urls", [])
    nuclei = summary.get("nuclei_findings", [])
    zap = summary.get("zap_findings", [])

    for host in alive_hosts:
        host_url = str(host.get("url", "")).strip()
        if not host_url:
            continue
        host_id = f"host:{host_url}"
        add_node(
            host_id,
            "host",
            host_url,
            f"status={host.get('status_code', '')} title={host.get('title', '')}",
        )
        for tech in host.get("tech") or []:
            tech_name = str(tech).strip()
            if not tech_name:
                continue
            tech_id = f"tech:{tech_name.lower()}"
            add_node(tech_id, "tech", tech_name)
            add_edge(host_id, tech_id, "runs")

    for item in urls:
        url_value = str(item.get("url", "")).strip()
        if not url_value:
            continue
        url_id = f"url:{url_value}"
        source_stage = str(item.get("source_stage", "unknown"))
        add_node(url_id, "url", url_value, f"source={source_stage}")
        host_key = _host_key(url_value)
        if host_key:
            host_id = f"host:{host_key}"
            if host_id in nodes:
                add_edge(host_id, url_id, "exposes")

    for finding in nuclei:
        template_id = str(finding.get("template_id", "unknown"))
        matched_at = str(finding.get("matched_at", "")).strip()
        severity = str(finding.get("severity", "unknown"))
        finding_id = f"nuclei:{template_id}:{severity.lower()}"
        add_node(
            finding_id,
            "nuclei",
            template_id,
            f"severity={severity}",
        )
        if matched_at:
            url_id = f"url:{matched_at}"
            host_id = f"host:{_host_key(matched_at)}"
            if url_id in nodes:
                add_edge(url_id, finding_id, "triggers")
            elif host_id in nodes:
                add_edge(host_id, finding_id, "triggers")

    for finding in zap:
        plugin_id = str(finding.get("plugin_id", "unknown"))
        alert = str(finding.get("alert", plugin_id))
        risk = str(finding.get("risk", "unknown"))
        url_value = str(finding.get("url", "")).strip()
        finding_id = f"zap:{plugin_id}:{risk.lower()}"
        add_node(
            finding_id,
            "zap",
            alert,
            f"plugin={plugin_id} risk={risk}",
        )
        if url_value:
            url_id = f"url:{url_value}"
            host_id = f"host:{_host_key(url_value)}"
            if url_id in nodes:
                add_edge(url_id, finding_id, "alerts")
            elif host_id in nodes:
                add_edge(host_id, finding_id, "alerts")

    type_counts = Counter(item["type"] for item in nodes.values())
    return {
        "meta": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "query": query,
            "included_types": sorted(include_types),
        },
        "type_counts": dict(type_counts),
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
    }
