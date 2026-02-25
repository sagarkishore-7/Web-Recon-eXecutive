from __future__ import annotations

from pathlib import Path
import time

from fastapi.testclient import TestClient

from wrx.gui import (
    build_action_cli_args,
    build_diff_for_runs,
    build_insights,
    create_app,
    list_presets_for_target,
    list_scan_profiles_for_target,
    list_runs_for_target,
    list_targets,
)
from wrx.workspace import init_workspace, write_json


def _write_completed_run(workspace: Path, run_id: str, summary: dict) -> None:
    run_dir = workspace / "runs" / run_id
    (run_dir / "data").mkdir(parents=True, exist_ok=True)
    (run_dir / "raw").mkdir(parents=True, exist_ok=True)

    write_json(
        run_dir / "run.json",
        {
            "run_id": run_id,
            "status": "completed",
            "started_at": "2026-02-24T00:00:00+00:00",
            "completed_at": "2026-02-24T00:05:00+00:00",
        },
    )
    write_json(run_dir / "data" / "summary.json", summary)
    for stage in ["subdomains", "probe", "crawl", "fuzz", "scan", "zap_baseline"]:
        write_json(run_dir / "data" / f"{stage}.json", {"status": "completed"})
    (run_dir / "report.html").write_text("<html><body>report</body></html>", encoding="utf-8")


def _summary(run_id: str, urls: list[str], nuclei: list[dict], zap: list[dict], timestamp: str) -> dict:
    return {
        "metadata": {
            "target": "juice-shop",
            "timestamp": timestamp,
            "preset": "demo",
            "run_id": run_id,
            "tool_versions": {},
            "artifact_paths": {},
        },
        "subdomains": [],
        "alive_hosts": [{"url": "http://localhost:3000", "status_code": 200, "title": "Juice Shop", "tech": ["Express"], "hash": "h"}],
        "urls": [{"url": value, "source_stage": "crawl", "discovered_at": timestamp, "hash": value} for value in urls],
        "nuclei_findings": nuclei,
        "zap_findings": zap,
        "counts": {
            "subdomains": 0,
            "alive_hosts": 1,
            "urls": len(urls),
            "nuclei_findings": len(nuclei),
            "zap_findings": len(zap),
        },
    }


def test_gui_listing_diff_and_insights(tmp_path: Path) -> None:
    workspace = init_workspace(tmp_path, "juice-shop")
    run_a = "20260224T010000000Z"
    run_b = "20260224T020000000Z"

    _write_completed_run(
        workspace,
        run_a,
        _summary(
            run_a,
            urls=["http://localhost:3000/login"],
            nuclei=[],
            zap=[{"plugin_id": "10021", "url": "http://localhost:3000", "risk": "Low"}],
            timestamp="2026-02-24T01:00:00+00:00",
        ),
    )
    _write_completed_run(
        workspace,
        run_b,
        _summary(
            run_b,
            urls=["http://localhost:3000/login", "http://localhost:3000/admin"],
            nuclei=[{"template_id": "missing-sri", "matched_at": "http://localhost:3000/", "severity": "medium", "name": "Missing SRI"}],
            zap=[{"plugin_id": "10021", "url": "http://localhost:3000", "risk": "Low"}, {"plugin_id": "10038", "url": "http://localhost:3000/admin", "risk": "Medium"}],
            timestamp="2026-02-24T02:00:00+00:00",
        ),
    )

    targets = list_targets(tmp_path)
    assert targets
    assert targets[0]["id"] == "juice-shop"

    runs = list_runs_for_target(tmp_path, "juice-shop")
    assert [run["run_id"] for run in runs] == [run_b, run_a]

    diff_payload = build_diff_for_runs(tmp_path, "juice-shop", current_run=run_b, previous_run=run_a)
    assert diff_payload["meta"]["current_run"] == run_b
    assert "http://localhost:3000/admin" in diff_payload["changes"]["urls"]["new"]
    assert "missing-sri::http://localhost:3000/" in diff_payload["changes"]["nuclei_findings"]["new"]

    insights = build_insights(tmp_path, "juice-shop", limit=5)
    assert insights["run_count"] == 2
    assert len(insights["trend"]) == 2
    assert "probe" in insights["stage_order"]
    assert len(insights["stage_matrix"]) == 2


def test_build_action_cli_args_and_presets(tmp_path: Path) -> None:
    workspace = init_workspace(tmp_path, "juice-shop")
    assert workspace.exists()

    presets = list_presets_for_target(tmp_path, "juice-shop")
    preset_names = {item["name"] for item in presets}
    assert {"demo", "quick", "bounty", "deep"} <= preset_names
    profiles = list_scan_profiles_for_target(tmp_path, "juice-shop")
    assert {"safe", "balanced", "deep"} <= {item["name"] for item in profiles}

    run_spec = build_action_cli_args(
        {
            "action": "run",
            "target": "juice-shop",
            "preset": "quick",
            "scan_profile": "balanced",
            "force": True,
            "dry_run": True,
            "local_demo": True,
            "with_scan": True,
            "triage": True,
            "ollama": True,
            "ollama_model": "qwen2.5:7b",
            "auto_init": True,
        }
    )
    assert run_spec["action"] == "run"
    assert "--dry-run" in run_spec["args"]
    assert "--local-demo" in run_spec["args"]
    assert "--scan-profile" in run_spec["args"]
    assert "--triage" in run_spec["args"]
    assert "--ollama" in run_spec["args"]
    assert run_spec["auto_init"] is True

    flow_spec = build_action_cli_args({"action": "flow", "target": "juice-shop", "with_scan": True})
    assert flow_spec["args"][:2] == ["flow", "juice-shop"]
    assert "--with-scan" in flow_spec["args"]

    export_spec = build_action_cli_args({"action": "export", "target": "juice-shop", "format": "sarif", "run_id": "r1"})
    assert export_spec["args"][:4] == ["export", "juice-shop", "--format", "sarif"]
    assert "--run-id" in export_spec["args"]


def test_gui_api_endpoints_and_job_lifecycle(tmp_path: Path) -> None:
    workspace = init_workspace(tmp_path, "juice-shop")
    run_id = "20260224T030000000Z"
    previous_id = "20260224T020000000Z"
    _write_completed_run(
        workspace,
        run_id,
        _summary(
            run_id,
            urls=["http://localhost:3000"],
            nuclei=[],
            zap=[],
            timestamp="2026-02-24T03:00:00+00:00",
        ),
    )
    _write_completed_run(
        workspace,
        previous_id,
        _summary(
            previous_id,
            urls=[],
            nuclei=[],
            zap=[],
            timestamp="2026-02-24T02:00:00+00:00",
        ),
    )

    app = create_app(tmp_path, default_target="juice-shop")
    client = TestClient(app)

    targets_resp = client.get("/api/targets")
    assert targets_resp.status_code == 200
    assert targets_resp.json()["default_target"] == "juice-shop"

    presets_resp = client.get("/api/presets", params={"target": "juice-shop"})
    assert presets_resp.status_code == 200
    assert any(item["name"] == "demo" for item in presets_resp.json()["presets"])

    profiles_resp = client.get("/api/scan-profiles", params={"target": "juice-shop"})
    assert profiles_resp.status_code == 200
    assert any(item["name"] == "safe" for item in profiles_resp.json()["profiles"])

    runs_resp = client.get("/api/runs", params={"target": "juice-shop"})
    assert runs_resp.status_code == 200
    assert len(runs_resp.json()["runs"]) == 2

    summary_resp = client.get("/api/summary", params={"target": "juice-shop", "run_id": run_id})
    assert summary_resp.status_code == 200
    assert summary_resp.json()["run_id"] == run_id

    insights_resp = client.get("/api/insights", params={"target": "juice-shop", "limit": 10})
    assert insights_resp.status_code == 200
    assert insights_resp.json()["run_count"] == 2

    diff_resp = client.get(
        "/api/diff",
        params={"target": "juice-shop", "current_run": run_id, "previous_run": previous_id},
    )
    assert diff_resp.status_code == 200
    assert diff_resp.json()["meta"]["previous_run"] == previous_id

    graph_resp = client.get("/api/graph", params={"target": "juice-shop", "run_id": run_id})
    assert graph_resp.status_code == 200
    assert graph_resp.json()["meta"]["total_nodes"] >= 1

    report_resp = client.get("/report", params={"target": "juice-shop", "run_id": run_id})
    assert report_resp.status_code == 200
    assert "report" in report_resp.text

    start_resp = client.post(
        "/api/actions/start",
        json={
            "action": "run",
            "target": "gui-action-target",
            "preset": "quick",
            "dry_run": True,
            "force": True,
            "auto_init": True,
        },
    )
    assert start_resp.status_code == 200
    job_id = start_resp.json()["job"]["id"]

    deadline = time.time() + 20
    final_status = ""
    while time.time() < deadline:
        job_resp = client.get(f"/api/actions/{job_id}", params={"tail": 2000})
        assert job_resp.status_code == 200
        job = job_resp.json()["job"]
        final_status = str(job.get("status", ""))
        if final_status in {"completed", "error", "cancelled"}:
            break
        time.sleep(0.2)

    assert final_status == "completed"
    actions_resp = client.get("/api/actions")
    assert actions_resp.status_code == 200
    assert any(item["id"] == job_id for item in actions_resp.json()["jobs"])

    # Restart app instance and ensure job history persists from SQLite store.
    app_restarted = create_app(tmp_path, default_target="juice-shop")
    client_restarted = TestClient(app_restarted)
    actions_restarted = client_restarted.get("/api/actions")
    assert actions_restarted.status_code == 200
    assert any(item["id"] == job_id for item in actions_restarted.json()["jobs"])
