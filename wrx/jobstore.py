"""Persistent SQLite job store for WRX GUI background actions."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  label TEXT NOT NULL,
  target TEXT NOT NULL,
  args_json TEXT NOT NULL,
  command_json TEXT NOT NULL,
  command_line TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  returncode INTEGER,
  cancel_requested INTEGER NOT NULL DEFAULT 0,
  pid INTEGER,
  log_path TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
"""


class JobStore:
    """SQLite-backed history for GUI jobs."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.commit()

    def mark_interrupted_jobs(self, finished_at: str) -> int:
        """Mark queued/running jobs as error after process restart."""
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE jobs
                SET status = 'error',
                    finished_at = ?,
                    error = CASE
                        WHEN error = '' THEN 'GUI process restarted before job completion'
                        ELSE error
                    END
                WHERE status IN ('queued', 'running')
                """,
                (finished_at,),
            )
            conn.commit()
            return int(cursor.rowcount or 0)

    def upsert_job(self, payload: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO jobs (
                    id, action, label, target, args_json, command_json, command_line,
                    status, created_at, started_at, finished_at, returncode,
                    cancel_requested, pid, log_path, error
                ) VALUES (
                    :id, :action, :label, :target, :args_json, :command_json, :command_line,
                    :status, :created_at, :started_at, :finished_at, :returncode,
                    :cancel_requested, :pid, :log_path, :error
                )
                ON CONFLICT(id) DO UPDATE SET
                    action = excluded.action,
                    label = excluded.label,
                    target = excluded.target,
                    args_json = excluded.args_json,
                    command_json = excluded.command_json,
                    command_line = excluded.command_line,
                    status = excluded.status,
                    created_at = excluded.created_at,
                    started_at = excluded.started_at,
                    finished_at = excluded.finished_at,
                    returncode = excluded.returncode,
                    cancel_requested = excluded.cancel_requested,
                    pid = excluded.pid,
                    log_path = excluded.log_path,
                    error = excluded.error
                """,
                {
                    "id": str(payload.get("id", "")),
                    "action": str(payload.get("action", "")),
                    "label": str(payload.get("label", "")),
                    "target": str(payload.get("target", "")),
                    "args_json": json.dumps(payload.get("args", [])),
                    "command_json": json.dumps(payload.get("command", [])),
                    "command_line": str(payload.get("command_line", "")),
                    "status": str(payload.get("status", "queued")),
                    "created_at": str(payload.get("created_at", "")),
                    "started_at": str(payload.get("started_at", "")),
                    "finished_at": str(payload.get("finished_at", "")),
                    "returncode": payload.get("returncode"),
                    "cancel_requested": 1 if payload.get("cancel_requested") else 0,
                    "pid": payload.get("pid"),
                    "log_path": str(payload.get("log_path", "")),
                    "error": str(payload.get("error", "")),
                },
            )
            conn.commit()

    def update_job(self, job_id: str, **fields: Any) -> None:
        if not fields:
            return

        assignments: list[str] = []
        values: list[Any] = []
        for key, value in fields.items():
            if key == "args":
                assignments.append("args_json = ?")
                values.append(json.dumps(value))
            elif key == "command":
                assignments.append("command_json = ?")
                values.append(json.dumps(value))
            elif key == "cancel_requested":
                assignments.append("cancel_requested = ?")
                values.append(1 if value else 0)
            else:
                assignments.append(f"{key} = ?")
                values.append(value)

        values.append(job_id)
        with self._lock, self._connect() as conn:
            conn.execute(
                f"UPDATE jobs SET {', '.join(assignments)} WHERE id = ?",
                values,
            )
            conn.commit()

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return self._row_to_dict(row) if row else None

    def list_jobs(self, limit: int = 30) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM jobs
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        args: list[str] = []
        command: list[str] = []
        try:
            args = [str(item) for item in json.loads(row["args_json"] or "[]")]
        except json.JSONDecodeError:
            args = []
        try:
            command = [str(item) for item in json.loads(row["command_json"] or "[]")]
        except json.JSONDecodeError:
            command = []

        return {
            "id": str(row["id"]),
            "action": str(row["action"]),
            "label": str(row["label"]),
            "target": str(row["target"]),
            "args": args,
            "command": command,
            "command_line": str(row["command_line"]),
            "status": str(row["status"]),
            "created_at": str(row["created_at"]),
            "started_at": str(row["started_at"]),
            "finished_at": str(row["finished_at"]),
            "returncode": row["returncode"],
            "cancel_requested": bool(row["cancel_requested"]),
            "pid": row["pid"],
            "log_path": str(row["log_path"]),
            "error": str(row["error"] or ""),
        }
