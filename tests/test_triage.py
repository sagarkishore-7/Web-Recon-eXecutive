from wrx.triage import generate_triage


def _summary() -> dict:
    return {
        "nuclei_findings": [
            {
                "template_id": "missing-sri",
                "severity": "medium",
                "name": "Missing SRI",
                "matched_at": "http://localhost:3000/a",
            },
            {
                "template_id": "missing-sri",
                "severity": "medium",
                "name": "Missing SRI",
                "matched_at": "http://localhost:3000/b",
            },
        ],
        "zap_findings": [
            {
                "plugin_id": "10021",
                "risk": "Low",
                "alert": "X-Content-Type-Options Header Missing",
                "url": "http://localhost:3000/a",
            }
        ],
    }


def test_triage_disabled_returns_empty() -> None:
    payload = generate_triage(_summary(), {"enabled": False})
    assert payload == {}


def test_triage_clusters_and_dry_run_ollama() -> None:
    payload = generate_triage(
        _summary(),
        {
            "enabled": True,
            "ollama": {"enabled": True, "model": "qwen2.5:7b", "base_url": "http://127.0.0.1:11434"},
        },
        dry_run=True,
    )
    assert payload["enabled"] is True
    assert payload["cluster_count"] >= 1
    assert payload["recommendations"]
    assert "dry-run" in payload["llm_error"]
