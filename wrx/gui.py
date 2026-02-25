"""Interactive WRX dashboard (GUI) powered by FastAPI."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import shlex
import subprocess
import sys
import threading
from typing import Any, Optional
import uuid

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from wrx import __version__
from wrx.analytics import build_asset_graph, build_coverage_drift, build_preset_trends
from wrx.config import DEFAULT_CONFIG, load_config
from wrx.diff import compute_diff
from wrx.jobstore import JobStore
from wrx.workspace import init_workspace, list_completed_runs, read_json, slugify_target

_KNOWN_STAGES = ("subdomains", "probe", "crawl", "fuzz", "scan", "zap_baseline")
_COUNT_KEYS = ("subdomains", "alive_hosts", "urls", "nuclei_findings", "zap_findings")


def _workspace_root(base_dir: Path) -> Path:
    return base_dir / "workspaces"


def _jobs_root(base_dir: Path) -> Path:
    return base_dir / ".wrx-gui" / "jobs"


def _jobs_db_path(base_dir: Path) -> Path:
    return base_dir / ".wrx-gui" / "jobs.db"


def _safe_relative(path: Path, base_dir: Path) -> str:
    try:
        return str(path.relative_to(base_dir))
    except ValueError:
        return str(path)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_iso(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _resolve_workspace(base_dir: Path, target: str) -> Path:
    root = _workspace_root(base_dir)
    direct = root / target
    if direct.is_dir():
        return direct

    slugged = root / slugify_target(target)
    if slugged.is_dir():
        return slugged

    raise ValueError(f"Target workspace not found: {target}")


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _as_int(value: Any, field: str, default: int, minimum: int = 0) -> int:
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"'{field}' must be an integer") from exc
    if parsed < minimum:
        raise ValueError(f"'{field}' must be >= {minimum}")
    return parsed


def _tail_text(path: Path, max_chars: int) -> str:
    if max_chars <= 0 or not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="ignore")
    if len(text) <= max_chars:
        return text
    return text[-max_chars:]


def list_targets(base_dir: Path) -> list[dict[str, Any]]:
    root = _workspace_root(base_dir)
    if not root.exists():
        return []

    rows: list[dict[str, Any]] = []
    for child in root.iterdir():
        if not child.is_dir():
            continue

        run_ids = list_completed_runs(child)
        latest_run = run_ids[-1] if run_ids else ""
        latest_summary: dict[str, Any] = {}
        if latest_run:
            latest_summary = read_json(child / "runs" / latest_run / "data" / "summary.json", default={})

        rows.append(
            {
                "id": child.name,
                "display_name": child.name,
                "run_count": len(run_ids),
                "latest_run": latest_run,
                "latest_timestamp": latest_summary.get("metadata", {}).get("timestamp", ""),
                "latest_counts": latest_summary.get("counts", {}),
            }
        )

    rows.sort(key=lambda item: (item.get("latest_timestamp", ""), item["id"]), reverse=True)
    return rows


def list_presets_for_target(base_dir: Path, target: Optional[str] = None) -> list[dict[str, Any]]:
    config: dict[str, Any]
    if target:
        try:
            workspace = _resolve_workspace(base_dir, target)
            config = load_config(workspace / "wrx.yaml")
        except ValueError:
            config = {"presets": DEFAULT_CONFIG.get("presets", {})}
    else:
        config = {"presets": DEFAULT_CONFIG.get("presets", {})}

    presets = config.get("presets", {})
    rows: list[dict[str, Any]] = []
    for name, payload in presets.items():
        if not isinstance(payload, dict):
            continue
        rows.append(
            {
                "name": name,
                "description": str(payload.get("description", "")),
                "stages": payload.get("stages", {}),
            }
        )
    return rows


def list_scan_profiles_for_target(base_dir: Path, target: Optional[str] = None) -> list[dict[str, Any]]:
    config: dict[str, Any]
    if target:
        try:
            workspace = _resolve_workspace(base_dir, target)
            config = load_config(workspace / "wrx.yaml")
        except ValueError:
            config = DEFAULT_CONFIG
    else:
        config = DEFAULT_CONFIG

    profiles = config.get("scan_profiles", {})
    rows: list[dict[str, Any]] = []
    for name, payload in profiles.items():
        if not isinstance(payload, dict):
            continue
        rows.append(
            {
                "name": str(name),
                "description": str(payload.get("description", "")),
                "settings": payload,
            }
        )
    rows.sort(key=lambda item: item["name"])
    return rows


def list_runs_for_target(base_dir: Path, target: str) -> list[dict[str, Any]]:
    workspace = _resolve_workspace(base_dir, target)
    run_ids = list_completed_runs(workspace)

    rows: list[dict[str, Any]] = []
    for run_id in reversed(run_ids):
        summary = read_json(workspace / "runs" / run_id / "data" / "summary.json", default={})
        run_meta = read_json(workspace / "runs" / run_id / "run.json", default={})
        counts = summary.get("counts", {})
        metadata = summary.get("metadata", {})

        started_at = str(run_meta.get("started_at", ""))
        completed_at = str(run_meta.get("completed_at", ""))
        duration_seconds: Optional[int] = None
        started_dt = _parse_iso(started_at)
        completed_dt = _parse_iso(completed_at)
        if started_dt and completed_dt:
            duration_seconds = max(0, int((completed_dt - started_dt).total_seconds()))

        rows.append(
            {
                "run_id": run_id,
                "preset": metadata.get("preset", "unknown"),
                "timestamp": metadata.get("timestamp", ""),
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_seconds": duration_seconds,
                "counts": {key: int(counts.get(key, 0) or 0) for key in _COUNT_KEYS},
                "status": run_meta.get("status", "unknown"),
            }
        )

    return rows


def _resolve_run_id(run_ids: list[str], run_id: Optional[str]) -> str:
    if not run_ids:
        raise ValueError("No completed runs found for target")
    if run_id is None:
        return run_ids[-1]
    if run_id not in run_ids:
        raise ValueError(f"Run not found: {run_id}")
    return run_id


def _stage_statuses(workspace: Path, run_id: str) -> list[dict[str, Any]]:
    data_dir = workspace / "runs" / run_id / "data"
    rows: list[dict[str, Any]] = []
    for stage in _KNOWN_STAGES:
        payload = read_json(data_dir / f"{stage}.json", default={})
        rows.append(
            {
                "stage": stage,
                "status": payload.get("status", "missing"),
                "reason": payload.get("reason", ""),
                "exit_code": payload.get("exit_code"),
            }
        )
    return rows


def load_summary_for_target(base_dir: Path, target: str, run_id: Optional[str] = None) -> dict[str, Any]:
    workspace = _resolve_workspace(base_dir, target)
    run_ids = list_completed_runs(workspace)
    resolved_run_id = _resolve_run_id(run_ids, run_id)

    summary_path = workspace / "runs" / resolved_run_id / "data" / "summary.json"
    summary = read_json(summary_path, default={})
    if not summary:
        raise ValueError(f"summary.json missing for run {resolved_run_id}")

    report_path = workspace / "runs" / resolved_run_id / "report.html"
    if not report_path.exists():
        report_path = workspace / "report.html"

    return {
        "target": workspace.name,
        "run_id": resolved_run_id,
        "summary": summary,
        "stage_statuses": _stage_statuses(workspace, resolved_run_id),
        "paths": {
            "summary_path": _safe_relative(summary_path, base_dir),
            "report_path": _safe_relative(report_path, base_dir),
            "report_url": f"/report?target={workspace.name}&run_id={resolved_run_id}",
        },
    }


def _impact_level(change_total: int) -> str:
    if change_total >= 25:
        return "high"
    if change_total >= 8:
        return "medium"
    if change_total > 0:
        return "low"
    return "none"


def build_diff_for_runs(
    base_dir: Path,
    target: str,
    current_run: Optional[str] = None,
    previous_run: Optional[str] = None,
) -> dict[str, Any]:
    workspace = _resolve_workspace(base_dir, target)
    run_ids = list_completed_runs(workspace)
    if len(run_ids) < 2:
        return {
            "meta": {
                "target": workspace.name,
                "message": "Need at least two completed runs for diff",
            },
            "changes": {},
            "cards": [],
        }

    resolved_current = _resolve_run_id(run_ids, current_run)
    current_index = run_ids.index(resolved_current)

    if previous_run is None:
        if current_index == 0:
            return {
                "meta": {
                    "target": workspace.name,
                    "current_run": resolved_current,
                    "message": "No earlier run exists for this selection",
                },
                "changes": {},
                "cards": [],
            }
        resolved_previous = run_ids[current_index - 1]
    else:
        resolved_previous = _resolve_run_id(run_ids, previous_run)
        if resolved_previous == resolved_current:
            raise ValueError("current_run and previous_run must be different")

    current_summary = read_json(workspace / "runs" / resolved_current / "data" / "summary.json", default={})
    previous_summary = read_json(workspace / "runs" / resolved_previous / "data" / "summary.json", default={})
    if not current_summary or not previous_summary:
        raise ValueError("Missing summary.json for selected runs")

    changes = compute_diff(current_summary, previous_summary)
    cards: list[dict[str, Any]] = []
    for key, value in changes.items():
        new_items = value.get("new", [])
        removed_items = value.get("removed", [])
        total = len(new_items) + len(removed_items)
        cards.append(
            {
                "category": key,
                "label": key.replace("_", " ").title(),
                "new_count": len(new_items),
                "removed_count": len(removed_items),
                "total_changes": total,
                "impact": _impact_level(total),
            }
        )

    cards.sort(key=lambda item: (item["total_changes"], item["label"]), reverse=True)

    return {
        "meta": {
            "target": workspace.name,
            "current_run": resolved_current,
            "previous_run": resolved_previous,
        },
        "changes": changes,
        "cards": cards,
    }


def build_insights(base_dir: Path, target: str, limit: int = 12) -> dict[str, Any]:
    workspace = _resolve_workspace(base_dir, target)
    runs = list_runs_for_target(base_dir, target)
    limited = runs[: max(1, limit)]

    trend = [
        {
            "run_id": row["run_id"],
            "preset": row.get("preset", "unknown"),
            "timestamp": row.get("timestamp", ""),
            "counts": row.get("counts", {}),
        }
        for row in reversed(limited)
    ]

    stage_matrix: list[dict[str, Any]] = []
    status_counter: Counter[str] = Counter()
    for row in limited:
        stage_map: dict[str, str] = {}
        for stage in _KNOWN_STAGES:
            payload = read_json(workspace / "runs" / row["run_id"] / "data" / f"{stage}.json", default={})
            status = str(payload.get("status", "missing"))
            stage_map[stage] = status
            status_counter[status] += 1
        stage_matrix.append(
            {
                "run_id": row["run_id"],
                "preset": row.get("preset", "unknown"),
                "stages": stage_map,
            }
        )

    totals: dict[str, int] = {}
    for key in _COUNT_KEYS:
        totals[key] = sum(int(row.get("counts", {}).get(key, 0) or 0) for row in limited)

    preset_trends = build_preset_trends(runs)
    coverage_drift = build_coverage_drift(runs)

    return {
        "target": target,
        "run_count": len(runs),
        "window_size": len(limited),
        "trend": trend,
        "stage_matrix": stage_matrix,
        "stage_order": list(_KNOWN_STAGES),
        "stage_status_totals": dict(status_counter),
        "totals": totals,
        "preset_trends": preset_trends,
        "coverage_drift": coverage_drift,
    }


def build_action_cli_args(payload: dict[str, Any]) -> dict[str, Any]:
    action = str(payload.get("action", "")).strip().lower()
    target = str(payload.get("target", "")).strip()

    if not action:
        raise ValueError("'action' is required")

    if action == "doctor":
        args = ["doctor"]
        if _as_bool(payload.get("strict"), default=False):
            args.append("--strict")
        return {"action": action, "target": "", "args": args, "label": "Doctor"}

    if action == "init":
        if not target:
            raise ValueError("'target' is required for init")
        return {"action": action, "target": target, "args": ["init", target], "label": f"Init {target}"}

    if action == "run":
        if not target:
            raise ValueError("'target' is required for run")
        preset = str(payload.get("preset", "quick")).strip() or "quick"
        args = ["run", target, "--preset", preset]
        concurrency = _as_int(payload.get("concurrency"), "concurrency", default=0, minimum=0)
        if concurrency > 0:
            args.extend(["--concurrency", str(concurrency)])
        if _as_bool(payload.get("force"), default=True):
            args.append("--force")
        if _as_bool(payload.get("dry_run"), default=False):
            args.append("--dry-run")
        if _as_bool(payload.get("local_demo"), default=False):
            args.append("--local-demo")
        if _as_bool(payload.get("with_scan"), default=False):
            args.append("--with-scan")
        scan_profile = str(payload.get("scan_profile", "")).strip()
        if scan_profile:
            args.extend(["--scan-profile", scan_profile])
        if _as_bool(payload.get("triage"), default=False):
            args.append("--triage")
        if _as_bool(payload.get("ollama"), default=False):
            args.append("--ollama")
            ollama_model = str(payload.get("ollama_model", "")).strip()
            if ollama_model:
                args.extend(["--ollama-model", ollama_model])
            ollama_url = str(payload.get("ollama_url", "")).strip()
            if ollama_url:
                args.extend(["--ollama-url", ollama_url])
        return {
            "action": action,
            "target": target,
            "args": args,
            "label": f"Run {preset} on {target}",
            "auto_init": _as_bool(payload.get("auto_init"), default=True),
        }

    if action == "diff":
        if not target:
            raise ValueError("'target' is required for diff")
        last = _as_int(payload.get("last"), "last", default=1, minimum=1)
        return {
            "action": action,
            "target": target,
            "args": ["diff", target, "--last", str(last)],
            "label": f"Diff {target}",
        }

    if action == "report":
        if not target:
            raise ValueError("'target' is required for report")
        return {"action": action, "target": target, "args": ["report", target], "label": f"Report {target}"}

    if action == "demo":
        demo_target = target or "juice-shop"
        args = ["demo", demo_target]
        if _as_bool(payload.get("dry_run"), default=False):
            args.append("--dry-run")
        if _as_bool(payload.get("no_open"), default=True):
            args.append("--no-open")
        if _as_bool(payload.get("keep_running"), default=False):
            args.append("--keep-running")
        return {"action": action, "target": demo_target, "args": args, "label": f"Demo {demo_target}"}

    if action == "flow":
        flow_target = target or "juice-shop"
        args = ["flow", flow_target]
        if _as_bool(payload.get("dry_run"), default=False):
            args.append("--dry-run")
        if _as_bool(payload.get("with_scan"), default=False):
            args.append("--with-scan")
        if _as_bool(payload.get("no_open"), default=True):
            args.append("--no-open")
        return {"action": action, "target": flow_target, "args": args, "label": f"Flow {flow_target}"}

    if action == "export":
        if not target:
            raise ValueError("'target' is required for export")
        export_format = str(payload.get("format", "markdown")).strip() or "markdown"
        args = ["export", target, "--format", export_format]
        run_id = str(payload.get("run_id", "")).strip()
        if run_id:
            args.extend(["--run-id", run_id])
        output_path = str(payload.get("out", "")).strip()
        if output_path:
            args.extend(["--out", output_path])
        jira_project = str(payload.get("jira_project", "")).strip()
        if jira_project:
            args.extend(["--jira-project", jira_project])
        jira_issue_type = str(payload.get("jira_issue_type", "")).strip()
        if jira_issue_type:
            args.extend(["--jira-issue-type", jira_issue_type])
        return {
            "action": action,
            "target": target,
            "args": args,
            "label": f"Export {export_format} for {target}",
        }

    raise ValueError(f"Unsupported action: {action}")


def _templates_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "templates"


def create_app(base_dir: Path, default_target: Optional[str] = None) -> FastAPI:
    """Create FastAPI app for WRX GUI."""
    app = FastAPI(title="WRX GUI", version=__version__)
    templates = Jinja2Templates(directory=str(_templates_dir()))

    base_dir = base_dir.resolve()
    default_target = default_target or ""
    jobs_dir = _jobs_root(base_dir)
    jobs_dir.mkdir(parents=True, exist_ok=True)
    job_store = JobStore(_jobs_db_path(base_dir))
    job_store.mark_interrupted_jobs(finished_at=_now_iso())
    processes: dict[str, subprocess.Popen] = {}
    lock = threading.Lock()

    def _serialize_job(record: dict[str, Any], tail_chars: int = 0) -> dict[str, Any]:
        payload = dict(record)
        if tail_chars > 0:
            payload["log_tail"] = _tail_text(Path(payload["log_path"]), tail_chars)
        return payload

    def _run_job(job_id: str, command: list[str], log_path: Path) -> None:
        started_at = _now_iso()
        job_store.update_job(job_id, status="running", started_at=started_at)

        log_path.parent.mkdir(parents=True, exist_ok=True)
        command_line = " ".join(shlex.quote(part) for part in command)

        process: Optional[subprocess.Popen] = None
        try:
            with log_path.open("w", encoding="utf-8") as handle:
                handle.write(f"$ {command_line}\n")
                handle.flush()

                try:
                    process = subprocess.Popen(
                        command,
                        cwd=str(base_dir),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                    )
                except OSError as exc:
                    handle.write(f"[wrx-gui] failed to start process: {exc}\n")
                    handle.flush()
                    job_store.update_job(
                        job_id,
                        status="error",
                        returncode=-1,
                        finished_at=_now_iso(),
                        error=str(exc),
                    )
                    return

                with lock:
                    processes[job_id] = process
                job_store.update_job(job_id, pid=process.pid)

                if process.stdout is not None:
                    for line in process.stdout:
                        handle.write(line)
                        handle.flush()

                returncode = process.wait()
        except Exception as exc:  # pragma: no cover - defensive fallback
            job_store.update_job(
                job_id,
                status="error",
                returncode=-2,
                error=str(exc),
                finished_at=_now_iso(),
            )
            return
        finally:
            with lock:
                processes.pop(job_id, None)

        record = job_store.get_job(job_id) or {}
        cancelled = bool(record.get("cancel_requested"))
        if cancelled and returncode != 0:
            status = "cancelled"
        else:
            status = "completed" if returncode == 0 else "error"
        job_store.update_job(
            job_id,
            status=status,
            returncode=returncode,
            finished_at=_now_iso(),
        )

    def _start_job(spec: dict[str, Any]) -> dict[str, Any]:
        job_id = uuid.uuid4().hex[:12]
        command = [sys.executable, "-m", "wrx.cli", *spec["args"]]
        log_path = jobs_dir / f"{job_id}.log"
        created_at = _now_iso()

        record = {
            "id": job_id,
            "action": spec["action"],
            "label": spec.get("label", spec["action"]),
            "target": spec.get("target", ""),
            "args": spec["args"],
            "command": command,
            "command_line": " ".join(shlex.quote(part) for part in command),
            "status": "queued",
            "created_at": created_at,
            "started_at": "",
            "finished_at": "",
            "returncode": None,
            "cancel_requested": False,
            "pid": None,
            "log_path": str(log_path),
            "error": "",
        }
        job_store.upsert_job(record)

        worker = threading.Thread(target=_run_job, args=(job_id, command, log_path), daemon=True)
        worker.start()
        snapshot = job_store.get_job(job_id) or record
        return _serialize_job(snapshot)

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        targets = list_targets(base_dir)
        target_ids = {item["id"] for item in targets}
        resolved_default = default_target if default_target in target_ids else ""
        if not resolved_default and targets:
            resolved_default = targets[0]["id"]

        return templates.TemplateResponse(
            "gui.html.j2",
            {
                "request": request,
                "app_version": __version__,
                "default_target": resolved_default,
            },
        )

    @app.get("/api/targets")
    async def api_targets() -> dict[str, Any]:
        targets = list_targets(base_dir)
        target_ids = {item["id"] for item in targets}
        resolved_default = default_target if default_target in target_ids else ""
        if not resolved_default and targets:
            resolved_default = targets[0]["id"]
        return {"targets": targets, "default_target": resolved_default}

    @app.get("/api/presets")
    async def api_presets(target: Optional[str] = Query(None, description="Workspace target id")) -> dict[str, Any]:
        return {"target": target or "", "presets": list_presets_for_target(base_dir, target)}

    @app.get("/api/scan-profiles")
    async def api_scan_profiles(target: Optional[str] = Query(None, description="Workspace target id")) -> dict[str, Any]:
        return {"target": target or "", "profiles": list_scan_profiles_for_target(base_dir, target)}

    @app.get("/api/runs")
    async def api_runs(target: str = Query(..., description="Workspace target id")) -> dict[str, Any]:
        try:
            runs = list_runs_for_target(base_dir, target)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"target": target, "runs": runs}

    @app.get("/api/summary")
    async def api_summary(
        target: str = Query(..., description="Workspace target id"),
        run_id: Optional[str] = Query(None, description="Specific run id"),
    ) -> dict[str, Any]:
        try:
            return load_summary_for_target(base_dir, target, run_id=run_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/insights")
    async def api_insights(
        target: str = Query(..., description="Workspace target id"),
        limit: int = Query(12, ge=1, le=50),
    ) -> dict[str, Any]:
        try:
            return build_insights(base_dir, target, limit=limit)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/diff")
    async def api_diff(
        target: str = Query(..., description="Workspace target id"),
        current_run: Optional[str] = Query(None, description="Current run id"),
        previous_run: Optional[str] = Query(None, description="Previous run id"),
    ) -> dict[str, Any]:
        try:
            return build_diff_for_runs(
                base_dir=base_dir,
                target=target,
                current_run=current_run,
                previous_run=previous_run,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/graph")
    async def api_graph(
        target: str = Query(..., description="Workspace target id"),
        run_id: Optional[str] = Query(None, description="Specific run id"),
        types: str = Query("", description="Comma-separated node types"),
        q: str = Query("", description="Search term"),
        max_nodes: int = Query(500, ge=25, le=2000),
    ) -> dict[str, Any]:
        try:
            summary_payload = load_summary_for_target(base_dir, target, run_id=run_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        include_types = {item.strip().lower() for item in types.split(",") if item.strip()}
        graph = build_asset_graph(
            summary_payload["summary"],
            include_types=include_types,
            query=q,
            max_nodes=max_nodes,
        )
        graph["meta"]["target"] = summary_payload.get("target", target)
        graph["meta"]["run_id"] = summary_payload.get("run_id", "")
        return graph

    @app.post("/api/actions/start")
    async def api_actions_start(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        try:
            spec = build_action_cli_args(payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if spec.get("action") == "run" and spec.get("target") and spec.get("auto_init", True):
            init_workspace(base_dir, spec["target"])

        job = _start_job(spec)
        return {"job": job}

    @app.get("/api/actions")
    async def api_actions(limit: int = Query(30, ge=1, le=200)) -> dict[str, Any]:
        rows = [_serialize_job(item) for item in job_store.list_jobs(limit=limit)]
        return {"jobs": rows}

    @app.get("/api/actions/{job_id}")
    async def api_action(job_id: str, tail: int = Query(10000, ge=0, le=200000)) -> dict[str, Any]:
        record = job_store.get_job(job_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        payload = _serialize_job(record, tail_chars=tail)
        return {"job": payload}

    @app.post("/api/actions/{job_id}/cancel")
    async def api_cancel_action(job_id: str) -> dict[str, Any]:
        record = job_store.get_job(job_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")

        if record.get("status") not in {"queued", "running"}:
            return {"job": _serialize_job(record), "message": "Job is not running"}

        job_store.update_job(job_id, cancel_requested=True)
        with lock:
            process = processes.get(job_id)
            if process is not None:
                process.terminate()
        updated = job_store.get_job(job_id) or record
        payload = _serialize_job(updated)
        return {"job": payload, "message": "Cancellation requested"}

    @app.get("/report", response_class=HTMLResponse)
    async def report_view(
        target: str = Query(..., description="Workspace target id"),
        run_id: Optional[str] = Query(None, description="Specific run id"),
    ) -> HTMLResponse:
        try:
            workspace = _resolve_workspace(base_dir, target)
            run_ids = list_completed_runs(workspace)
            resolved_run_id = _resolve_run_id(run_ids, run_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        report_path = workspace / "runs" / resolved_run_id / "report.html"
        if not report_path.exists():
            report_path = workspace / "report.html"
        if not report_path.exists():
            raise HTTPException(status_code=404, detail="report.html not found")

        return HTMLResponse(report_path.read_text(encoding="utf-8", errors="ignore"))

    return app
