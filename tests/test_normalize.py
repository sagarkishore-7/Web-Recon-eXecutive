from pathlib import Path

from wrx.normalize.ffuf import parse_ffuf_json
from wrx.normalize.httpx import parse_httpx_jsonl
from wrx.normalize.nuclei import parse_nuclei_jsonl


def test_parse_httpx_jsonl(tmp_path: Path) -> None:
    sample = tmp_path / "httpx.jsonl"
    sample.write_text(
        '{"url":"https://a.example.com","status_code":200,"title":"A","tech":["nginx"]}\n',
        encoding="utf-8",
    )

    items = parse_httpx_jsonl(sample)

    assert len(items) == 1
    assert items[0].url == "https://a.example.com"
    assert items[0].status_code == 200
    assert items[0].tech == ["nginx"]


def test_parse_nuclei_jsonl(tmp_path: Path) -> None:
    sample = tmp_path / "nuclei.jsonl"
    sample.write_text(
        '{"template-id":"xss-detect","matched-at":"https://a.example.com","info":{"severity":"high","name":"XSS"}}\n',
        encoding="utf-8",
    )

    findings = parse_nuclei_jsonl(sample)

    assert len(findings) == 1
    assert findings[0].template_id == "xss-detect"
    assert findings[0].matched_at == "https://a.example.com"
    assert findings[0].severity == "high"


def test_parse_ffuf_json(tmp_path: Path) -> None:
    sample = tmp_path / "ffuf.json"
    sample.write_text(
        '{"results":[{"url":"https://a.example.com/admin"}]}'
        ,encoding="utf-8",
    )

    urls = parse_ffuf_json(sample)

    assert len(urls) == 1
    assert urls[0].url == "https://a.example.com/admin"
    assert urls[0].source_stage == "fuzz"
