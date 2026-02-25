"""Pipeline runner for WRX stages."""

from __future__ import annotations

import asyncio
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from rich.console import Console

from wrx.models import AliveHost, DiscoveredURL, NucleiFinding, Summary, TargetMetadata, ZapFinding, now_utc_iso
from wrx.stages import crawl, fuzz, probe, scan, subdomains, zap_baseline
from wrx.triage import generate_triage
from wrx.wordlists import derive_context_words
from wrx.workspace import read_json, run_paths, write_json


@dataclass
class StageStatus:
    stage: str
    status: str
    message: str
    duration_seconds: float


@dataclass
class RunResult:
    run_id: str
    summary_path: Path
    stage_statuses: list[StageStatus]
    summary: dict[str, Any]


class AsyncCommandExecutor:
    """Bounded async subprocess runner with streaming logs."""

    def __init__(self, concurrency: int, dry_run: bool, console: Console) -> None:
        self._semaphore = asyncio.Semaphore(max(1, concurrency))
        self._dry_run = dry_run
        self._console = console

    async def run(self, cmd: list[str], log_path: Path, timeout: int) -> int:
        async with self._semaphore:
            return await self._run_single(cmd, log_path, timeout)

    async def _run_single(self, cmd: list[str], log_path: Path, timeout: int) -> int:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        command_text = " ".join(shlex.quote(part) for part in cmd)

        with log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(f"$ {command_text}\n")
            log_file.flush()

            if self._dry_run:
                self._console.print(f"[cyan][dry-run][/cyan] {command_text}")
                return 0

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            async def _stream_output() -> None:
                assert proc.stdout is not None
                while True:
                    chunk = await proc.stdout.read(8192)
                    if not chunk:
                        break
                    log_file.write(chunk.decode("utf-8", errors="ignore"))
                    log_file.flush()

            stream_task = asyncio.create_task(_stream_output())
            try:
                await asyncio.wait_for(proc.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                log_file.write(f"\n[wrx] command timed out after {timeout}s\n")
                log_file.flush()
                return 124
            finally:
                await stream_task

            return int(proc.returncode or 0)


def detect_tool_versions() -> dict[str, str]:
    """Collect best-effort external tool versions."""
    tool_versions: dict[str, str] = {}
    tools = ["subfinder", "httpx", "katana", "ffuf", "nuclei", "docker"]

    for tool in tools:
        if shutil.which(tool) is None:
            tool_versions[tool] = "missing"
            continue

        version_value = "available"
        for args in (["-version"], ["--version"], ["version"]):
            try:
                result = subprocess.run(
                    [tool, *args],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                continue

            output = (result.stdout or result.stderr or "").strip().splitlines()
            if output:
                version_value = output[0].strip()
                break

        tool_versions[tool] = version_value

    return tool_versions


def _load_cached_stage(data_root: Path, stage: str, force: bool) -> Optional[dict[str, Any]]:
    stage_path = data_root / f"{stage}.json"
    if force or not stage_path.exists():
        return None
    payload = read_json(stage_path, default={})
    if payload:
        payload["status"] = payload.get("status") or "resumed"
    return payload


def _write_disabled_stage(data_root: Path, stage: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": "disabled",
        "reason": f"Stage '{stage}' disabled by preset",
    }
    if stage == "subdomains":
        payload["subdomains"] = []
    elif stage == "probe":
        payload["alive_hosts"] = []
    elif stage in {"crawl", "fuzz"}:
        payload["urls"] = []
    elif stage == "scan":
        payload["nuclei_findings"] = []
    elif stage == "zap_baseline":
        payload["zap_findings"] = []
        payload["artifacts"] = {
            "zap_json": f"raw/{stage}/zap.json",
            "zap_html": f"raw/{stage}/zap.html",
        }

    write_json(data_root / f"{stage}.json", payload)
    return payload


async def run_pipeline(
    target: str,
    workspace: Path,
    run_id: str,
    run_config: dict[str, Any],
    concurrency: int,
    force: bool,
    dry_run: bool,
    console: Console,
) -> RunResult:
    paths = run_paths(workspace, run_id)
    raw_root = paths["raw"]
    data_root = paths["data"]
    raw_root.mkdir(parents=True, exist_ok=True)
    data_root.mkdir(parents=True, exist_ok=True)

    executor = AsyncCommandExecutor(concurrency=concurrency, dry_run=dry_run, console=console)
    stage_statuses: list[StageStatus] = []

    stages_enabled = run_config.get("stages", {})
    tool_args = run_config.get("tool_args", {})
    timeouts = run_config.get("timeouts", {})
    rate_limits = run_config.get("rate_limits", {})
    fuzz_context = run_config.get("fuzz_context", {})
    seed_hosts = [item for item in run_config.get("seed_hosts", []) if isinstance(item, str)]
    scan_hosts_only = bool(run_config.get("scan_hosts_only", False))
    zap_config = run_config.get("zap", {})

    aggregated_subdomains: list[str] = []
    aggregated_alive_hosts: list[dict[str, Any]] = []
    aggregated_urls: dict[str, dict[str, Any]] = {}
    aggregated_findings: dict[str, dict[str, Any]] = {}
    aggregated_zap_findings: dict[str, dict[str, Any]] = {}
    artifact_paths: dict[str, str] = {}

    async def execute_stage(stage: str, coro_factory: Any) -> dict[str, Any]:
        started = time.perf_counter()
        console.print(f"[bold blue]Stage:[/bold blue] {stage}")

        if not stages_enabled.get(stage, False):
            payload = _write_disabled_stage(data_root, stage)
            stage_raw_dir = raw_root / stage
            stage_raw_dir.mkdir(parents=True, exist_ok=True)
            (stage_raw_dir / "logs.txt").write_text(
                f"[wrx] stage '{stage}' disabled by preset.\n",
                encoding="utf-8",
            )
            duration = time.perf_counter() - started
            console.print(f"[yellow]Skipped[/yellow] {stage} ({payload.get('reason', '')})")
            stage_statuses.append(
                StageStatus(stage=stage, status="disabled", message=payload.get("reason", ""), duration_seconds=duration)
            )
            return payload

        cached = _load_cached_stage(data_root, stage, force=force)
        if cached is not None:
            duration = time.perf_counter() - started
            console.print(f"[cyan]Resumed[/cyan] {stage} from cached output")
            stage_statuses.append(
                StageStatus(stage=stage, status="resumed", message="Used cached stage output", duration_seconds=duration)
            )
            return cached

        try:
            payload = await coro_factory()
        except Exception as exc:  # pragma: no cover - defensive fallback
            payload = {"status": "error", "reason": str(exc)}

        duration = time.perf_counter() - started
        stage_statuses.append(
            StageStatus(
                stage=stage,
                status=payload.get("status", "unknown"),
                message=payload.get("reason", "") or payload.get("message", ""),
                duration_seconds=duration,
            )
        )
        console.print(f"[green]Done[/green] {stage} (status={payload.get('status', 'unknown')}, {duration:.2f}s)")
        return payload

    subdomains_payload = await execute_stage(
        "subdomains",
        lambda: subdomains.execute(
            target=target,
            raw_root=raw_root,
            data_root=data_root,
            run_cmd=executor.run,
            args=list(tool_args.get("subdomains", [])),
            timeout=int(timeouts.get("subdomains", 180)),
        ),
    )
    aggregated_subdomains = sorted(set(subdomains_payload.get("subdomains", [])))

    probe_payload = await execute_stage(
        "probe",
        lambda: probe.execute(
            target=target,
            hosts=aggregated_subdomains,
            seed_hosts=seed_hosts,
            raw_root=raw_root,
            data_root=data_root,
            run_cmd=executor.run,
            args=list(tool_args.get("probe", [])),
            timeout=int(timeouts.get("probe", 240)),
        ),
    )
    aggregated_alive_hosts = list(probe_payload.get("alive_hosts", []))

    crawl_payload = await execute_stage(
        "crawl",
        lambda: crawl.execute(
            alive_hosts=[item.get("url", "") for item in aggregated_alive_hosts],
            raw_root=raw_root,
            data_root=data_root,
            run_cmd=executor.run,
            args=list(tool_args.get("crawl", [])),
            timeout=int(timeouts.get("crawl", 300)),
        ),
    )

    for item in crawl_payload.get("urls", []):
        url = item.get("url")
        if url:
            aggregated_urls[url] = item

    context_words: list[str] = []
    if bool(fuzz_context.get("enabled", True)):
        context_words = derive_context_words(
            [item.get("url", "") for item in crawl_payload.get("urls", [])],
            max_words=int(fuzz_context.get("max_words", 120)),
        )

    fuzz_payload = await execute_stage(
        "fuzz",
        lambda: fuzz.execute(
            alive_hosts=[item.get("url", "") for item in aggregated_alive_hosts],
            raw_root=raw_root,
            data_root=data_root,
            run_cmd=executor.run,
            args=list(tool_args.get("fuzz", [])),
            timeout=int(timeouts.get("fuzz", 300)),
            rate_limit=int(rate_limits.get("fuzz", 20)),
            context_words=context_words,
        ),
    )

    for item in fuzz_payload.get("urls", []):
        url = item.get("url")
        if url:
            aggregated_urls[url] = item

    if scan_hosts_only:
        scan_targets = [item.get("url", "") for item in aggregated_alive_hosts if item.get("url")]
    else:
        scan_targets = list(aggregated_urls.keys())
        if not scan_targets:
            scan_targets = [item.get("url", "") for item in aggregated_alive_hosts if item.get("url")]
    if not scan_targets:
        scan_targets = list(seed_hosts)
    if not scan_targets:
        scan_targets = [target]

    scan_payload = await execute_stage(
        "scan",
        lambda: scan.execute(
            targets=scan_targets,
            raw_root=raw_root,
            data_root=data_root,
            run_cmd=executor.run,
            args=list(tool_args.get("scan", [])),
            timeout=int(timeouts.get("scan", 420)),
        ),
    )

    for item in scan_payload.get("nuclei_findings", []):
        key = item.get("hash") or f"{item.get('template_id','')}::{item.get('matched_at','')}"
        aggregated_findings[key] = item

    zap_target_url = ""
    if seed_hosts:
        zap_target_url = seed_hosts[0]
    elif aggregated_alive_hosts:
        zap_target_url = str(aggregated_alive_hosts[0].get("url", ""))
    elif isinstance(target, str) and target.startswith(("http://", "https://")):
        zap_target_url = target

    zap_payload = await execute_stage(
        "zap_baseline",
        lambda: zap_baseline.execute(
            target_url=zap_target_url,
            raw_root=raw_root,
            data_root=data_root,
            run_cmd=executor.run,
            docker_image=str(zap_config.get("docker_image", "owasp/zap2docker-stable")),
            baseline_args=[str(item) for item in zap_config.get("baseline_args", ["-m", "3"])],
            timeout=int(zap_config.get("timeout_seconds", timeouts.get("zap_baseline", 900))),
            localhost_only=bool(zap_config.get("localhost_only", False)),
        ),
    )
    for item in zap_payload.get("zap_findings", []):
        key = item.get("hash") or f"{item.get('plugin_id','')}::{item.get('url','')}"
        aggregated_zap_findings[key] = item

    zap_artifacts = zap_payload.get("artifacts", {})
    if isinstance(zap_artifacts, dict):
        for key in ("zap_json", "zap_html"):
            value = zap_artifacts.get(key)
            if isinstance(value, str) and value:
                artifact_paths[key] = value

    metadata = TargetMetadata(
        target=target,
        timestamp=now_utc_iso(),
        preset=run_config.get("selected_preset", "unknown"),
        run_id=run_id,
        tool_versions=detect_tool_versions(),
        artifact_paths=artifact_paths,
    )

    summary_model = Summary(
        metadata=metadata,
        subdomains=aggregated_subdomains,
        alive_hosts=[AliveHost(**item) for item in aggregated_alive_hosts],
        urls=[DiscoveredURL(**item) for item in aggregated_urls.values()],
        nuclei_findings=[NucleiFinding(**item) for item in aggregated_findings.values()],
        zap_findings=[ZapFinding(**item) for item in aggregated_zap_findings.values()],
    )

    summary_payload = summary_model.to_dict()
    summary_payload["fuzz_context_words"] = [str(item) for item in fuzz_payload.get("context_words", [])]
    summary_payload["triage"] = generate_triage(
        summary_payload,
        triage_config=run_config.get("triage", {}),
        dry_run=dry_run,
    )
    write_json(paths["summary"], summary_payload)

    return RunResult(
        run_id=run_id,
        summary_path=paths["summary"],
        stage_statuses=stage_statuses,
        summary=summary_payload,
    )
