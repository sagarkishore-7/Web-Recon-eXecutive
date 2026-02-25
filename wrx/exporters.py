"""Output connectors for WRX findings and recon summaries."""

from __future__ import annotations

import json
from typing import Any


def _level_from_severity(value: str) -> str:
    text = str(value or "").lower()
    if text in {"critical", "high"}:
        return "error"
    if text in {"medium"}:
        return "warning"
    return "note"


def export_markdown(summary: dict[str, Any], target: str, run_id: str) -> str:
    counts = summary.get("counts", {})
    lines = [
        f"# WRX Findings Export: {target}",
        "",
        f"- Run ID: `{run_id}`",
        f"- Preset: `{summary.get('metadata', {}).get('preset', 'unknown')}`",
        f"- Generated: `{summary.get('metadata', {}).get('timestamp', '')}`",
        "",
        "## Counts",
        "",
        f"- Subdomains: {counts.get('subdomains', 0)}",
        f"- Alive Hosts: {counts.get('alive_hosts', 0)}",
        f"- URLs: {counts.get('urls', 0)}",
        f"- Nuclei Findings: {counts.get('nuclei_findings', 0)}",
        f"- ZAP Findings: {counts.get('zap_findings', 0)}",
        "",
        "## Nuclei Findings",
        "",
    ]
    nuclei = summary.get("nuclei_findings", [])
    if not nuclei:
        lines.append("- None")
    else:
        for item in nuclei:
            lines.append(
                f"- `{item.get('severity', 'unknown')}` `{item.get('template_id', 'unknown')}` "
                f"at `{item.get('matched_at', '-')}`"
            )

    lines.extend(["", "## ZAP Findings", ""])
    zap = summary.get("zap_findings", [])
    if not zap:
        lines.append("- None")
    else:
        for item in zap:
            lines.append(
                f"- `{item.get('risk', 'unknown')}` `{item.get('alert', item.get('plugin_id', 'unknown'))}` "
                f"at `{item.get('url', '-')}`"
            )
    lines.append("")
    return "\n".join(lines)


def export_sarif(summary: dict[str, Any], target: str, run_id: str) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}

    for item in summary.get("nuclei_findings", []):
        rule_id = str(item.get("template_id", "nuclei-unknown"))
        rules.setdefault(rule_id, {"id": rule_id, "name": rule_id})
        uri = str(item.get("matched_at", ""))
        results.append(
            {
                "ruleId": rule_id,
                "level": _level_from_severity(str(item.get("severity", "unknown"))),
                "message": {"text": str(item.get("name", rule_id))},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri or target},
                        }
                    }
                ],
            }
        )

    for item in summary.get("zap_findings", []):
        plugin = str(item.get("plugin_id", "zap-unknown"))
        rule_id = f"zap-{plugin}"
        rules.setdefault(rule_id, {"id": rule_id, "name": str(item.get("alert", rule_id))})
        uri = str(item.get("url", ""))
        results.append(
            {
                "ruleId": rule_id,
                "level": _level_from_severity(str(item.get("risk", "unknown"))),
                "message": {"text": str(item.get("alert", rule_id))},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri or target},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wrx",
                        "informationUri": "https://github.com/",
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": run_id},
                "invocations": [{"executionSuccessful": True}],
                "results": results,
            }
        ],
    }


def export_github_issues(summary: dict[str, Any], target: str, run_id: str) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for item in summary.get("nuclei_findings", []):
        issues.append(
            {
                "title": f"[WRX][{target}] {item.get('template_id', 'nuclei')} on {item.get('matched_at', '-')}",
                "labels": ["security", "wrx", "nuclei", str(item.get("severity", "unknown")).lower()],
                "body": (
                    f"Run: {run_id}\n\n"
                    f"Template: {item.get('template_id', '-')}\n"
                    f"Severity: {item.get('severity', '-')}\n"
                    f"Name: {item.get('name', '-')}\n"
                    f"Matched At: {item.get('matched_at', '-')}\n"
                ),
            }
        )
    for item in summary.get("zap_findings", []):
        issues.append(
            {
                "title": f"[WRX][{target}] ZAP {item.get('plugin_id', 'unknown')} {item.get('alert', '')}",
                "labels": ["security", "wrx", "zap", str(item.get("risk", "unknown")).lower()],
                "body": (
                    f"Run: {run_id}\n\n"
                    f"Plugin: {item.get('plugin_id', '-')}\n"
                    f"Risk: {item.get('risk', '-')}\n"
                    f"Alert: {item.get('alert', '-')}\n"
                    f"URL: {item.get('url', '-')}\n"
                    f"Confidence: {item.get('confidence', '-')}\n"
                ),
            }
        )
    return issues


def export_jira_issues(
    summary: dict[str, Any],
    target: str,
    run_id: str,
    project_key: str = "SEC",
    issue_type: str = "Task",
) -> list[dict[str, Any]]:
    tickets: list[dict[str, Any]] = []
    for issue in export_github_issues(summary, target=target, run_id=run_id):
        tickets.append(
            {
                "fields": {
                    "project": {"key": project_key},
                    "issuetype": {"name": issue_type},
                    "summary": issue["title"][:200],
                    "description": issue["body"],
                    "labels": issue["labels"],
                }
            }
        )
    return tickets


def render_export_payload(
    fmt: str,
    summary: dict[str, Any],
    target: str,
    run_id: str,
    jira_project: str = "SEC",
    jira_issue_type: str = "Task",
) -> tuple[str, str]:
    """Return (file_extension, content) for requested export format."""
    normalized = fmt.strip().lower()
    if normalized == "markdown":
        return "md", export_markdown(summary, target=target, run_id=run_id)
    if normalized == "sarif":
        return "sarif", json.dumps(export_sarif(summary, target=target, run_id=run_id), indent=2, sort_keys=True)
    if normalized == "github":
        return "json", json.dumps(export_github_issues(summary, target=target, run_id=run_id), indent=2, sort_keys=True)
    if normalized == "jira":
        return "json", json.dumps(
            export_jira_issues(
                summary,
                target=target,
                run_id=run_id,
                project_key=jira_project,
                issue_type=jira_issue_type,
            ),
            indent=2,
            sort_keys=True,
        )
    raise ValueError(f"Unsupported export format: {fmt}")
