from wrx.analytics import build_asset_graph, build_coverage_drift, build_preset_trends


def _summary() -> dict:
    return {
        "alive_hosts": [{"url": "http://localhost:3000", "status_code": 200, "title": "Juice Shop", "tech": ["Express"]}],
        "urls": [
            {"url": "http://localhost:3000/login", "source_stage": "crawl"},
            {"url": "http://localhost:3000/api/users", "source_stage": "crawl"},
        ],
        "nuclei_findings": [
            {"template_id": "missing-sri", "severity": "medium", "name": "Missing SRI", "matched_at": "http://localhost:3000/login"}
        ],
        "zap_findings": [
            {"plugin_id": "10021", "risk": "Low", "alert": "X-Content-Type-Options Header Missing", "url": "http://localhost:3000/login"}
        ],
    }


def test_build_asset_graph_links_entities() -> None:
    graph = build_asset_graph(_summary())
    assert graph["meta"]["total_nodes"] > 0
    assert graph["meta"]["total_edges"] > 0
    node_types = {item["type"] for item in graph["nodes"]}
    assert {"host", "url", "tech", "nuclei", "zap"} <= node_types

    filtered = build_asset_graph(_summary(), include_types={"host", "url"}, query="login")
    assert all(node["type"] in {"host", "url"} for node in filtered["nodes"])
    assert any("login" in node["label"] for node in filtered["nodes"])


def test_trend_rollups_and_drift() -> None:
    runs = [
        {"run_id": "r2", "preset": "quick", "counts": {"alive_hosts": 2, "urls": 10, "nuclei_findings": 2, "zap_findings": 4}},
        {"run_id": "r1", "preset": "quick", "counts": {"alive_hosts": 1, "urls": 7, "nuclei_findings": 1, "zap_findings": 3}},
    ]
    preset = build_preset_trends(runs)
    assert preset["rollups"]["quick"]["runs"] == 2
    assert float(preset["rollups"]["quick"]["averages"]["urls"]) > 0

    drift = build_coverage_drift(runs)
    assert len(drift) == 1
    assert drift[0]["delta_surface"] > 0
