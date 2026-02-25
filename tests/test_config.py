from wrx.config import build_default_config, resolve_run_config


def test_demo_preset_is_available_and_localhost_safe() -> None:
    config = build_default_config("juice-shop")
    resolved = resolve_run_config(config, preset="demo")

    assert resolved["stages"]["subdomains"] is False
    assert resolved["stages"]["fuzz"] is False
    assert resolved["stages"]["scan"] is False
    assert resolved["stages"]["zap_baseline"] is True
    assert resolved["seed_hosts"] == ["http://localhost:3000"]
    assert resolved["zap"]["localhost_only"] is True
    assert resolved["selected_scan_profile"] == "safe"


def test_scan_profile_override_changes_resolution() -> None:
    config = build_default_config("juice-shop")
    resolved = resolve_run_config(config, preset="quick", scan_profile_override="deep")
    assert resolved["selected_scan_profile"] == "deep"
    assert "-severity" in resolved["tool_args"]["scan"]
