from pathlib import Path

from wrx.normalize.zap import parse_zap_json


def test_parse_zap_json_fixture() -> None:
    fixture = Path("examples/fixtures/zap_baseline_sample.json")
    findings = parse_zap_json(fixture)

    assert len(findings) >= 2
    first = findings[0]
    assert first.plugin_id
    assert first.alert
    assert first.risk
    assert first.hash

    urls = {item.url for item in findings}
    assert any(url.startswith("http://host.docker.internal:3000") for url in urls)


def test_parse_zap_json_stable_hash(tmp_path: Path) -> None:
    sample = tmp_path / "zap.json"
    sample.write_text(
        '{"site":[{"@name":"http://localhost:3000","alerts":[{"pluginid":"1","alert":"Test Alert","riskcode":"1","confidence":"Low","instances":[{"uri":"http://localhost:3000/"}]}]}]}',
        encoding="utf-8",
    )

    one = parse_zap_json(sample)
    two = parse_zap_json(sample)

    assert len(one) == 1
    assert len(two) == 1
    assert one[0].hash == two[0].hash
