"""HTML report generation for WRX."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from wrx.workspace import current_run_id, read_json


def _severity_counts(findings: list[dict[str, Any]]) -> list[tuple[str, int]]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    counter = Counter((item.get("severity") or "unknown").lower() for item in findings)
    return sorted(counter.items(), key=lambda pair: (order.get(pair[0], 99), pair[0]))


def _zap_risk_counts(findings: list[dict[str, Any]]) -> list[tuple[str, int]]:
    order = {"high": 0, "medium": 1, "low": 2, "informational": 3, "unknown": 4}
    counter = Counter((item.get("risk") or "unknown").lower() for item in findings)
    return sorted(counter.items(), key=lambda pair: (order.get(pair[0], 99), pair[0]))


def generate_report(workspace: Path, run_id: Optional[str] = None) -> Path:
    resolved_run_id = run_id or current_run_id(workspace)
    if not resolved_run_id:
        raise ValueError("No run available to report")

    run_dir = workspace / "runs" / resolved_run_id
    summary_path = run_dir / "data" / "summary.json"
    summary = read_json(summary_path, default={})
    if not summary:
        raise ValueError("summary.json not found for selected run")

    module_root = Path(__file__).resolve().parent.parent
    templates_dir = module_root / "templates"

    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html.j2")

    findings = summary.get("nuclei_findings", [])
    zap_findings = summary.get("zap_findings", [])
    artifact_paths = summary.get("metadata", {}).get("artifact_paths", {})
    rendered = template.render(
        metadata=summary.get("metadata", {}),
        counts=summary.get("counts", {}),
        subdomains=summary.get("subdomains", []),
        alive_hosts=summary.get("alive_hosts", []),
        urls=summary.get("urls", []),
        findings=findings,
        severity_counts=_severity_counts(findings),
        zap_findings=zap_findings,
        zap_risk_counts=_zap_risk_counts(zap_findings),
        triage=summary.get("triage", {}),
        fuzz_context_words=summary.get("fuzz_context_words", []),
        zap_artifacts=artifact_paths,
        raw_links={
            "subdomains": "raw/subdomains/",
            "probe": "raw/probe/",
            "crawl": "raw/crawl/",
            "fuzz": "raw/fuzz/",
            "scan": "raw/scan/",
            "zap_baseline": "raw/zap_baseline/",
        },
    )

    workspace_report = workspace / "report.html"
    run_report = run_dir / "report.html"
    workspace_report.write_text(rendered, encoding="utf-8")
    run_report.write_text(rendered, encoding="utf-8")
    return workspace_report
