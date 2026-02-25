"""Workspace and run lifecycle helpers for WRX."""

from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .config import write_default_config


def slugify_target(target: str) -> str:
    """Make a filesystem-safe workspace directory name."""
    cleaned = target.strip().lower()
    cleaned = re.sub(r"^https?://", "", cleaned)
    cleaned = cleaned.strip("/")
    slug = re.sub(r"[^a-zA-Z0-9._-]", "_", cleaned)
    return slug or "target"


def workspace_root(base_dir: Path, target: str) -> Path:
    return base_dir / "workspaces" / slugify_target(target)


def now_run_id() -> str:
    # Include milliseconds to avoid collisions for rapid sequential runs.
    timestamp = datetime.now(timezone.utc)
    return timestamp.strftime("%Y%m%dT%H%M%S") + f"{int(timestamp.microsecond / 1000):03d}Z"


def init_workspace(base_dir: Path, target: str) -> Path:
    root = workspace_root(base_dir, target)
    (root / "runs").mkdir(parents=True, exist_ok=True)
    (root / "raw").mkdir(parents=True, exist_ok=True)
    (root / "data").mkdir(parents=True, exist_ok=True)

    config_path = root / "wrx.yaml"
    if not config_path.exists():
        write_default_config(config_path, target)

    return root


def ensure_workspace(base_dir: Path, target: str) -> Path:
    root = workspace_root(base_dir, target)
    if not root.exists():
        raise FileNotFoundError(
            f"Workspace for target '{target}' not found. Run 'wrx init {target}' first."
        )
    return root


def _run_meta_path(workspace: Path, run_id: str) -> Path:
    return workspace / "runs" / run_id / "run.json"


def current_run_id(workspace: Path) -> Optional[str]:
    marker = workspace / "current_run.txt"
    if not marker.exists():
        return None
    value = marker.read_text(encoding="utf-8").strip()
    return value or None


def set_current_run_id(workspace: Path, run_id: str) -> None:
    (workspace / "current_run.txt").write_text(run_id, encoding="utf-8")


def list_completed_runs(workspace: Path) -> list[str]:
    runs_dir = workspace / "runs"
    if not runs_dir.exists():
        return []

    run_ids: list[str] = []
    for child in runs_dir.iterdir():
        if not child.is_dir():
            continue
        meta = read_json(child / "run.json", default={})
        if meta.get("status") == "completed":
            run_ids.append(child.name)

    return sorted(run_ids)


def start_or_resume_run(workspace: Path, force: bool = False) -> tuple[str, Path, bool]:
    """Start a new run or resume an in-progress run.

    Returns (run_id, run_dir, resumed).
    """
    existing = current_run_id(workspace)
    if existing and not force:
        existing_meta = read_json(_run_meta_path(workspace, existing), default={})
        if existing_meta.get("status") == "in_progress":
            return existing, workspace / "runs" / existing, True

    run_id = now_run_id()
    run_dir = workspace / "runs" / run_id
    (run_dir / "raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "data").mkdir(parents=True, exist_ok=True)

    write_json(
        _run_meta_path(workspace, run_id),
        {
            "run_id": run_id,
            "status": "in_progress",
            "started_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    set_current_run_id(workspace, run_id)
    return run_id, run_dir, False


def mark_run_completed(workspace: Path, run_id: str) -> None:
    meta_path = _run_meta_path(workspace, run_id)
    meta = read_json(meta_path, default={})
    meta["status"] = "completed"
    meta["completed_at"] = datetime.now(timezone.utc).isoformat()
    write_json(meta_path, meta)


def sync_latest_aliases(workspace: Path, run_id: str) -> None:
    """Sync latest run outputs to workspace root raw/data directories."""
    run_dir = workspace / "runs" / run_id
    for name in ["raw", "data"]:
        src = run_dir / name
        dst = workspace / name
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def run_paths(workspace: Path, run_id: str) -> dict[str, Path]:
    run_dir = workspace / "runs" / run_id
    raw = run_dir / "raw"
    data = run_dir / "data"
    return {
        "run_dir": run_dir,
        "raw": raw,
        "data": data,
        "summary": data / "summary.json",
        "report": run_dir / "report.html",
    }


def latest_summary_path(workspace: Path) -> Path:
    run_id = current_run_id(workspace)
    if not run_id:
        return workspace / "data" / "summary.json"
    return workspace / "runs" / run_id / "data" / "summary.json"
