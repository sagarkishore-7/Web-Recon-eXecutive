"""Configuration loading, defaults, and preset resolution for WRX."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

import yaml


DEFAULT_CONFIG: dict[str, Any] = {
    "default_concurrency": 4,
    "default_scan_profile": "safe",
    "timeouts": {
        "subdomains": 180,
        "probe": 240,
        "crawl": 300,
        "fuzz": 300,
        "scan": 420,
        "zap_baseline": 900,
    },
    "rate_limits": {
        "fuzz": 20,
    },
    "fuzz_context": {
        "enabled": True,
        "max_words": 120,
    },
    "tool_args": {
        "subdomains": ["-silent"],
        "probe": ["-silent", "-json"],
        "crawl": ["-silent", "-jsonl"],
        "fuzz": [],
        "scan": ["-silent", "-jsonl"],
    },
    "zap": {
        "docker_image": "owasp/zap2docker-stable",
        "baseline_args": ["-m", "3"],
        "timeout_seconds": 900,
        "localhost_only": False,
    },
    "triage": {
        "enabled": False,
        "cluster_by": "signature",
        "ollama": {
            "enabled": False,
            "base_url": "http://127.0.0.1:11434",
            "model": "qwen2.5:7b",
            "temperature": 0.1,
            "timeout_seconds": 30,
        },
    },
    "scan_profiles": {
        "safe": {
            "description": "Conservative defaults for repeatable recon.",
            "nuclei_args": ["-rate-limit", "12", "-timeout", "8", "-severity", "critical,high,medium"],
            "nuclei_timeout_seconds": 300,
            "zap_baseline_args": ["-m", "2"],
            "zap_timeout_seconds": 600,
            "nuclei_allow_tags": ["misconfig", "tech"],
        },
        "balanced": {
            "description": "Balanced signal and depth.",
            "nuclei_args": ["-rate-limit", "20", "-timeout", "10", "-severity", "critical,high,medium"],
            "nuclei_timeout_seconds": 600,
            "zap_baseline_args": ["-m", "3"],
            "zap_timeout_seconds": 900,
            "nuclei_allow_tags": ["misconfig", "tech", "exposure"],
        },
        "deep": {
            "description": "Deeper passive coverage and broader severities.",
            "nuclei_args": ["-rate-limit", "25", "-timeout", "12", "-severity", "critical,high,medium,low"],
            "nuclei_timeout_seconds": 900,
            "zap_baseline_args": ["-m", "5"],
            "zap_timeout_seconds": 1200,
            "nuclei_allow_tags": ["misconfig", "tech", "exposure", "cve"],
        },
    },
    "presets": {
        "demo": {
            "description": "Safe localhost demo against OWASP Juice Shop on http://localhost:3000.",
            "concurrency": 2,
            "scan_profile": "safe",
            "seed_hosts": ["http://localhost:3000"],
            "stages": {
                "subdomains": False,
                "probe": True,
                "crawl": True,
                "fuzz": False,
                "scan": False,
                "zap_baseline": True,
                "report": True,
            },
            "tool_args": {
                "probe": ["-silent", "-json", "-no-color"],
                "crawl": ["-silent", "-jsonl", "-depth", "2", "-concurrency", "5", "-timeout", "8"],
                "scan": ["-silent", "-jsonl", "-rate-limit", "20", "-timeout", "10", "-severity", "critical,high"],
            },
            "zap": {
                "docker_image": "owasp/zap2docker-stable",
                "baseline_args": ["-m", "3"],
                "timeout_seconds": 900,
                "localhost_only": True,
            },
            "timeouts": {
                "probe": 120,
                "crawl": 90,
                "scan": 120,
                "zap_baseline": 900,
            },
        },
        "quick": {
            "description": "Fast signal collection for triage.",
            "concurrency": 3,
            "scan_profile": "safe",
            "stages": {
                "subdomains": True,
                "probe": True,
                "crawl": False,
                "fuzz": False,
                "scan": True,
                "zap_baseline": False,
                "report": True,
            },
            "tool_args": {
                "scan": ["-severity", "critical,high"],
            },
        },
        "bounty": {
            "description": "Balanced preset for bug bounty workflows.",
            "concurrency": 5,
            "scan_profile": "balanced",
            "stages": {
                "subdomains": True,
                "probe": True,
                "crawl": True,
                "fuzz": True,
                "scan": True,
                "zap_baseline": False,
                "report": True,
            },
            "tool_args": {
                "scan": ["-severity", "critical,high,medium"],
            },
            "timeouts": {
                "scan": 900,
            },
        },
        "deep": {
            "description": "Thorough but slower reconnaissance pass.",
            "concurrency": 8,
            "scan_profile": "deep",
            "stages": {
                "subdomains": True,
                "probe": True,
                "crawl": True,
                "fuzz": True,
                "scan": True,
                "zap_baseline": False,
                "report": True,
            },
            "tool_args": {
                "crawl": ["-depth", "4"],
                "scan": ["-severity", "critical,high,medium,low"],
            },
            "timeouts": {
                "crawl": 600,
                "scan": 900,
            },
            "rate_limits": {
                "fuzz": 10,
            },
        },
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


def build_default_config(target: str) -> dict[str, Any]:
    cfg = deepcopy(DEFAULT_CONFIG)
    cfg["target"] = target
    return cfg


def write_default_config(path: Path, target: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    config = build_default_config(target)
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return build_default_config(target="")
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return _deep_merge(DEFAULT_CONFIG, loaded)


def resolve_run_config(
    config: dict[str, Any],
    preset: str,
    cli_concurrency: Optional[int] = None,
    scan_profile_override: Optional[str] = None,
) -> dict[str, Any]:
    presets = config.get("presets", {})
    if preset not in presets:
        raise ValueError(f"Preset '{preset}' not found in wrx.yaml")

    selected = presets[preset]
    resolved = _deep_merge(config, selected)
    resolved["selected_preset"] = preset

    tool_args = _deep_merge(config.get("tool_args", {}), selected.get("tool_args", {}))
    timeouts = _deep_merge(config.get("timeouts", {}), selected.get("timeouts", {}))
    rate_limits = _deep_merge(config.get("rate_limits", {}), selected.get("rate_limits", {}))
    fuzz_context = _deep_merge(config.get("fuzz_context", {}), selected.get("fuzz_context", {}))
    zap = _deep_merge(config.get("zap", {}), selected.get("zap", {}))
    triage = _deep_merge(config.get("triage", {}), selected.get("triage", {}))

    scan_profiles = _deep_merge(config.get("scan_profiles", {}), selected.get("scan_profiles", {}))
    chosen_profile = scan_profile_override or selected.get("scan_profile") or config.get("default_scan_profile", "safe")
    if chosen_profile not in scan_profiles:
        available = ", ".join(sorted(scan_profiles.keys()))
        raise ValueError(f"Scan profile '{chosen_profile}' not found. Available: {available}")
    profile = scan_profiles.get(chosen_profile, {})

    profile_nuclei_args = [str(item) for item in profile.get("nuclei_args", [])]
    existing_scan_args = [str(item) for item in tool_args.get("scan", [])]
    allow_tags = [str(item) for item in profile.get("nuclei_allow_tags", []) if str(item).strip()]
    if allow_tags and "-tags" not in profile_nuclei_args and "-tags" not in existing_scan_args:
        profile_nuclei_args.extend(["-tags", ",".join(allow_tags)])
    tool_args["scan"] = profile_nuclei_args + existing_scan_args

    if "scan" not in selected.get("timeouts", {}) and profile.get("nuclei_timeout_seconds"):
        timeouts["scan"] = int(profile["nuclei_timeout_seconds"])
    if "baseline_args" not in selected.get("zap", {}) and profile.get("zap_baseline_args"):
        zap["baseline_args"] = [str(item) for item in profile.get("zap_baseline_args", [])]
    if "timeout_seconds" not in selected.get("zap", {}) and profile.get("zap_timeout_seconds"):
        zap["timeout_seconds"] = int(profile["zap_timeout_seconds"])

    resolved["tool_args"] = tool_args
    resolved["timeouts"] = timeouts
    resolved["rate_limits"] = rate_limits
    resolved["fuzz_context"] = fuzz_context
    resolved["zap"] = zap
    resolved["triage"] = triage
    resolved["scan_profiles"] = scan_profiles
    resolved["scan_profile"] = chosen_profile
    resolved["selected_scan_profile"] = chosen_profile
    resolved["scan_profile_settings"] = profile

    if cli_concurrency is not None:
        resolved["default_concurrency"] = cli_concurrency

    return resolved
