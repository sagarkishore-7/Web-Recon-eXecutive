from wrx.diff import compute_diff


def test_compute_diff_identifies_new_and_removed_items() -> None:
    previous = {
        "subdomains": ["a.example.com", "b.example.com"],
        "alive_hosts": [{"url": "https://a.example.com"}],
        "urls": [{"url": "https://a.example.com/login"}],
        "nuclei_findings": [
            {"template_id": "xss-detect", "matched_at": "https://a.example.com/login"}
        ],
        "zap_findings": [
            {"plugin_id": "10021", "url": "https://a.example.com/login"}
        ],
    }
    current = {
        "subdomains": ["a.example.com", "c.example.com"],
        "alive_hosts": [{"url": "https://a.example.com"}, {"url": "https://c.example.com"}],
        "urls": [{"url": "https://a.example.com/login"}, {"url": "https://c.example.com/admin"}],
        "nuclei_findings": [
            {"template_id": "sqli-detect", "matched_at": "https://c.example.com/admin"}
        ],
        "zap_findings": [
            {"plugin_id": "10038", "url": "https://c.example.com/admin"}
        ],
    }

    payload = compute_diff(current, previous)

    assert payload["subdomains"]["new"] == ["c.example.com"]
    assert payload["subdomains"]["removed"] == ["b.example.com"]
    assert payload["alive_hosts"]["new"] == ["https://c.example.com"]
    assert payload["alive_hosts"]["removed"] == []
    assert payload["urls"]["new"] == ["https://c.example.com/admin"]
    assert payload["nuclei_findings"]["new"] == ["sqli-detect::https://c.example.com/admin"]
    assert payload["nuclei_findings"]["removed"] == ["xss-detect::https://a.example.com/login"]
    assert payload["zap_findings"]["new"] == ["10038::https://c.example.com/admin"]
    assert payload["zap_findings"]["removed"] == ["10021::https://a.example.com/login"]
