"""Optional local-first finding triage with Ollama integration."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections import Counter
from hashlib import sha1
from typing import Any


def _signature_nuclei(item: dict[str, Any]) -> str:
    template = str(item.get("template_id", "unknown")).strip().lower()
    severity = str(item.get("severity", "unknown")).strip().lower()
    name = str(item.get("name", template)).strip().lower()
    return f"nuclei::{template}::{severity}::{name}"


def _signature_zap(item: dict[str, Any]) -> str:
    plugin = str(item.get("plugin_id", "unknown")).strip().lower()
    risk = str(item.get("risk", "unknown")).strip().lower()
    alert = str(item.get("alert", plugin)).strip().lower()
    return f"zap::{plugin}::{risk}::{alert}"


def _cluster_findings(summary: dict[str, Any]) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for finding in summary.get("nuclei_findings", []):
        signature = _signature_nuclei(finding)
        bucket = buckets.setdefault(
            signature,
            {
                "id": sha1(signature.encode("utf-8")).hexdigest()[:12],
                "source": "nuclei",
                "signature": signature,
                "title": str(finding.get("name", finding.get("template_id", "unknown"))),
                "severity": str(finding.get("severity", "unknown")),
                "count": 0,
                "examples": [],
            },
        )
        bucket["count"] += 1
        matched = str(finding.get("matched_at", ""))
        if matched and matched not in bucket["examples"] and len(bucket["examples"]) < 5:
            bucket["examples"].append(matched)

    for finding in summary.get("zap_findings", []):
        signature = _signature_zap(finding)
        bucket = buckets.setdefault(
            signature,
            {
                "id": sha1(signature.encode("utf-8")).hexdigest()[:12],
                "source": "zap",
                "signature": signature,
                "title": str(finding.get("alert", finding.get("plugin_id", "unknown"))),
                "severity": str(finding.get("risk", "unknown")),
                "count": 0,
                "examples": [],
            },
        )
        bucket["count"] += 1
        url = str(finding.get("url", ""))
        if url and url not in bucket["examples"] and len(bucket["examples"]) < 5:
            bucket["examples"].append(url)

    clusters = list(buckets.values())
    clusters.sort(key=lambda item: (int(item.get("count", 0)), str(item.get("severity", ""))), reverse=True)
    return clusters


def _default_recommendations(clusters: list[dict[str, Any]]) -> list[str]:
    severity_counts = Counter(str(item.get("severity", "unknown")).lower() for item in clusters)
    source_counts = Counter(str(item.get("source", "unknown")).lower() for item in clusters)
    lines = [
        f"Prioritize {severity_counts.get('critical', 0) + severity_counts.get('high', 0)} high-impact cluster(s) first.",
        f"Validate recurring exposures across sources: nuclei={source_counts.get('nuclei', 0)}, zap={source_counts.get('zap', 0)}.",
        "Apply quick wins: security headers, CSP hardening, and least-privilege endpoint access.",
    ]
    return lines


def _ollama_generate(
    base_url: str,
    model: str,
    prompt: str,
    temperature: float,
    timeout_seconds: int,
) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": float(temperature)},
    }
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=max(3, int(timeout_seconds))) as response:
        data = json.loads(response.read().decode("utf-8", errors="ignore"))
    return str(data.get("response", "")).strip()


def generate_triage(
    summary: dict[str, Any],
    triage_config: dict[str, Any],
    dry_run: bool = False,
) -> dict[str, Any]:
    """Generate deduplicated local triage with optional Ollama summarization."""
    if not bool(triage_config.get("enabled", False)):
        return {}

    clusters = _cluster_findings(summary)
    payload: dict[str, Any] = {
        "enabled": True,
        "cluster_count": len(clusters),
        "clusters": clusters,
        "recommendations": _default_recommendations(clusters),
        "llm_summary": "",
        "llm_error": "",
        "llm_used": False,
    }

    ollama = triage_config.get("ollama", {})
    ollama_enabled = bool(ollama.get("enabled", False))
    if dry_run or not ollama_enabled or not clusters:
        if dry_run and ollama_enabled:
            payload["llm_error"] = "dry-run mode: ollama call skipped"
        return payload

    base_url = str(ollama.get("base_url", "http://127.0.0.1:11434"))
    model = str(ollama.get("model", "qwen2.5:7b"))
    timeout_seconds = int(ollama.get("timeout_seconds", 30))
    temperature = float(ollama.get("temperature", 0.1))

    top_clusters = clusters[:8]
    prompt_lines = [
        "You are a security triage assistant.",
        "Summarize the findings and provide concise remediation priorities.",
        "Respond in short bullets.",
        "",
        "Top clusters:",
    ]
    for idx, cluster in enumerate(top_clusters, start=1):
        prompt_lines.append(
            f"{idx}. [{cluster['source']}] {cluster['title']} "
            f"(severity/risk={cluster['severity']}, count={cluster['count']}, examples={', '.join(cluster['examples'])})"
        )

    prompt = "\n".join(prompt_lines)
    try:
        llm_text = _ollama_generate(
            base_url=base_url,
            model=model,
            prompt=prompt,
            temperature=temperature,
            timeout_seconds=timeout_seconds,
        )
        payload["llm_summary"] = llm_text
        payload["llm_used"] = bool(llm_text)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        payload["llm_error"] = str(exc)

    return payload
