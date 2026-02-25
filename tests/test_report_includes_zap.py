import json
from pathlib import Path

from wrx.report import generate_report


def test_report_renders_zap_section(tmp_path: Path) -> None:
    workspace = tmp_path / "workspaces" / "juice-shop"
    run_id = "20260219T000000Z"
    run_data = workspace / "runs" / run_id / "data"
    run_data.mkdir(parents=True, exist_ok=True)

    summary = {
        "metadata": {
            "target": "juice-shop",
            "timestamp": "2026-02-19T00:00:00+00:00",
            "preset": "demo",
            "run_id": run_id,
            "tool_versions": {},
            "artifact_paths": {
                "zap_json": "raw/zap_baseline/zap.json",
                "zap_html": "raw/zap_baseline/zap.html"
            }
        },
        "subdomains": [],
        "alive_hosts": [{"url": "http://localhost:3000", "status_code": 200, "title": "Juice Shop", "tech": [], "hash": "x"}],
        "urls": [],
        "nuclei_findings": [],
        "zap_findings": [
            {
                "plugin_id": "10021",
                "alert": "X-Content-Type-Options Header Missing",
                "risk": "Low",
                "confidence": "Medium",
                "url": "http://localhost:3000/",
                "evidence": "header",
                "description": "desc",
                "solution": "fix",
                "reference": "ref",
                "cweid": "16",
                "wascid": "15",
                "instances": 1,
                "hash": "zaphash"
            }
        ],
        "counts": {
            "subdomains": 0,
            "alive_hosts": 1,
            "urls": 0,
            "nuclei_findings": 0,
            "zap_findings": 1
        }
    }
    (run_data / "summary.json").write_text(json.dumps(summary), encoding="utf-8")

    report_path = generate_report(workspace, run_id=run_id)
    rendered = report_path.read_text(encoding="utf-8")

    assert "ZAP Baseline Findings" in rendered
    assert "X-Content-Type-Options Header Missing" in rendered
    assert "zap.json" in rendered
