from pathlib import Path

from wrx.jobstore import JobStore


def _record(job_id: str) -> dict:
    return {
        "id": job_id,
        "action": "run",
        "label": "Run quick",
        "target": "juice-shop",
        "args": ["run", "juice-shop", "--preset", "quick", "--dry-run"],
        "command": ["python", "-m", "wrx.cli", "run", "juice-shop"],
        "command_line": "python -m wrx.cli run juice-shop",
        "status": "running",
        "created_at": "2026-02-24T00:00:00+00:00",
        "started_at": "2026-02-24T00:00:01+00:00",
        "finished_at": "",
        "returncode": None,
        "cancel_requested": False,
        "pid": 1234,
        "log_path": "tmp/job.log",
        "error": "",
    }


def test_jobstore_persists_and_marks_interrupted(tmp_path: Path) -> None:
    db_path = tmp_path / ".wrx-gui" / "jobs.db"
    store = JobStore(db_path)
    store.upsert_job(_record("abc123"))

    loaded = store.get_job("abc123")
    assert loaded is not None
    assert loaded["status"] == "running"
    assert loaded["args"][0] == "run"

    restarted = JobStore(db_path)
    rows = restarted.list_jobs(limit=10)
    assert len(rows) == 1
    assert rows[0]["id"] == "abc123"

    changed = restarted.mark_interrupted_jobs("2026-02-24T00:05:00+00:00")
    assert changed == 1
    updated = restarted.get_job("abc123")
    assert updated is not None
    assert updated["status"] == "error"
    assert updated["finished_at"] == "2026-02-24T00:05:00+00:00"
