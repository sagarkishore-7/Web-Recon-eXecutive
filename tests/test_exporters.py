import json

from wrx.exporters import render_export_payload


def _summary() -> dict:
    return {
        "metadata": {"preset": "quick", "timestamp": "2026-02-24T00:00:00+00:00"},
        "counts": {"subdomains": 0, "alive_hosts": 1, "urls": 3, "nuclei_findings": 1, "zap_findings": 1},
        "nuclei_findings": [
            {
                "template_id": "missing-sri",
                "severity": "medium",
                "name": "Missing SRI",
                "matched_at": "http://localhost:3000/",
            }
        ],
        "zap_findings": [
            {
                "plugin_id": "10021",
                "risk": "Low",
                "alert": "X-Content-Type-Options Header Missing",
                "url": "http://localhost:3000/",
                "confidence": "Medium",
            }
        ],
    }


def test_render_export_payload_formats() -> None:
    ext, md = render_export_payload("markdown", summary=_summary(), target="juice-shop", run_id="r1")
    assert ext == "md"
    assert "WRX Findings Export" in md

    ext, sarif_text = render_export_payload("sarif", summary=_summary(), target="juice-shop", run_id="r1")
    assert ext == "sarif"
    sarif = json.loads(sarif_text)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]

    _, github_text = render_export_payload("github", summary=_summary(), target="juice-shop", run_id="r1")
    github_payload = json.loads(github_text)
    assert isinstance(github_payload, list)
    assert github_payload

    _, jira_text = render_export_payload("jira", summary=_summary(), target="juice-shop", run_id="r1")
    jira_payload = json.loads(jira_text)
    assert isinstance(jira_payload, list)
    assert jira_payload[0]["fields"]["project"]["key"] == "SEC"
