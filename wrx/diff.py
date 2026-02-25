"""Diff computation between WRX runs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from wrx.models import now_utc_iso
from wrx.workspace import list_completed_runs, read_json, write_json


def _subdomains(summary: dict[str, Any]) -> set[str]:
    return {str(item) for item in summary.get("subdomains", [])}


def _alive_hosts(summary: dict[str, Any]) -> set[str]:
    return {str(item.get("url", "")) for item in summary.get("alive_hosts", []) if item.get("url")}


def _urls(summary: dict[str, Any]) -> set[str]:
    return {str(item.get("url", "")) for item in summary.get("urls", []) if item.get("url")}


def _nuclei_findings(summary: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for item in summary.get("nuclei_findings", []):
        template_id = str(item.get("template_id", ""))
        matched_at = str(item.get("matched_at", ""))
        if template_id and matched_at:
            values.add(f"{template_id}::{matched_at}")
    return values


def _zap_findings(summary: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for item in summary.get("zap_findings", []):
        plugin_id = str(item.get("plugin_id", ""))
        url = str(item.get("url", ""))
        if plugin_id:
            values.add(f"{plugin_id}::{url}")
    return values


def _pair_diff(current: set[str], previous: set[str]) -> dict[str, list[str]]:
    return {
        "new": sorted(current - previous),
        "removed": sorted(previous - current),
    }


def compute_diff(current_summary: dict[str, Any], previous_summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "subdomains": _pair_diff(_subdomains(current_summary), _subdomains(previous_summary)),
        "alive_hosts": _pair_diff(_alive_hosts(current_summary), _alive_hosts(previous_summary)),
        "urls": _pair_diff(_urls(current_summary), _urls(previous_summary)),
        "nuclei_findings": _pair_diff(_nuclei_findings(current_summary), _nuclei_findings(previous_summary)),
        "zap_findings": _pair_diff(_zap_findings(current_summary), _zap_findings(previous_summary)),
    }


def compute_workspace_diff(workspace: Path, last: int = 1) -> dict[str, Any]:
    if last < 1:
        raise ValueError("--last must be >= 1")

    run_ids = list_completed_runs(workspace)
    if len(run_ids) <= last:
        raise ValueError("Not enough completed runs to diff")

    current_run = run_ids[-1]
    previous_run = run_ids[-1 - last]

    current_summary_path = workspace / "runs" / current_run / "data" / "summary.json"
    previous_summary_path = workspace / "runs" / previous_run / "data" / "summary.json"

    current_summary = read_json(current_summary_path, default={})
    previous_summary = read_json(previous_summary_path, default={})
    if not current_summary or not previous_summary:
        raise ValueError("Missing summary.json for one of the runs")

    diff_payload = {
        "meta": {
            "current_run": current_run,
            "previous_run": previous_run,
            "compared_at": now_utc_iso(),
            "last": last,
        },
        "changes": compute_diff(current_summary, previous_summary),
    }

    write_json(workspace / "data" / "diff.json", diff_payload)
    write_json(workspace / "runs" / current_run / "data" / "diff.json", diff_payload)
    return diff_payload
